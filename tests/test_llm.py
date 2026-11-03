"""Offline checks for provider selection, the Ollama switch and the OpenRouter fallback."""
import sys
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
import llm  # noqa: E402
import llm_cache  # noqa: E402

_VARS = ("OLLAMA", "OLLAMA_BASE_URL", "OLLAMA_MODEL", "LLM_PROVIDER", "LLM_API_KEY", "LLM_MODEL",
         "LLM_BASE_URL", "OPENAI_API_KEY", "OPENAI_MODEL", "OPENAI_BASE_URL", "ANTHROPIC_API_KEY",
         "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENROUTER_API_KEY", "OPENROUTER_MODEL",
         "OPENROUTER_LLM_MODEL", "OPENROUTER_BASE_URL", "LLM_CACHE", "LLM_CACHE_TTL_SECONDS",
         "LLM_CACHE_MAX_ENTRIES")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    for v in _VARS:
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("CLAWNET_LLM_CACHE_PATH", str(tmp_path / "llm_cache.json"))


def test_default_is_openai_and_legacy_key_still_works(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-legacy")
    p = llm.resolve()
    assert (p.name, p.api_key, p.model) == ("openai", "sk-legacy", "gpt-5.4-mini")


@pytest.mark.parametrize("name,model,url", [
    ("openai", "gpt-5.4-mini", "https://api.openai.com/v1"),
    ("anthropic", "claude-haiku-5-5", "https://api.anthropic.com/v1"),
    ("gemini", "gemini-3.6-flash", "https://generativelanguage.googleapis.com/v1beta"),
    ("openrouter", "openai/gpt-5.4-mini", "https://openrouter.ai/api/v1"),
])
def test_llm_api_key_serves_every_provider(monkeypatch, name, model, url):
    monkeypatch.setenv("LLM_PROVIDER", name)
    monkeypatch.setenv("LLM_API_KEY", "k")
    p = llm.resolve()
    assert (p.name, p.api_key, p.model, p.base_url) == (name, "k", model, url)


def test_unknown_provider_is_refused(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "bogus")
    with pytest.raises(SystemExit):
        llm.resolve()


def test_ollama_switch_is_local_only(monkeypatch):
    monkeypatch.setenv("OLLAMA", "yes")
    monkeypatch.setenv("LLM_API_KEY", "cloud-key")
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key")
    p = llm.resolve()
    assert p.local and p.base_url == "http://localhost:11434/v1" and p.model == "llama3.1"
    assert llm.fallback() is None and llm.available()      # never falls back to the cloud
    monkeypatch.setenv("OLLAMA", "no")
    assert llm.resolve().name == "openai"


def test_openrouter_is_the_fallback_unless_it_is_the_choice(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("LLM_API_KEY", "a")
    assert llm.fallback() is None
    monkeypatch.setenv("OPENROUTER_API_KEY", "or")
    monkeypatch.setenv("OPENROUTER_LLM_MODEL", "x/y")       # the older .env spelling
    assert (llm.fallback().name, llm.fallback().model) == ("openrouter", "x/y")
    monkeypatch.setenv("LLM_PROVIDER", "openrouter")
    assert llm.fallback() is None


class _Resp:
    def __init__(self, ok, body=None):
        self.ok, self.body = ok, body or {}

    def raise_for_status(self):
        if not self.ok:
            raise requests.HTTPError("500")

    def json(self):
        return self.body


def test_request_shapes_and_fallback(monkeypatch):
    calls = []

    def post(url, **kw):
        calls.append((url, kw))
        if "anthropic" in url:
            return _Resp(False)
        if "openrouter" in url:
            return _Resp(True, {"choices": [{"message": {"content": "via openrouter"}}]})
        return _Resp(True, {"content": [{"type": "text", "text": "hi"}]})

    monkeypatch.setattr(requests, "post", post)
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("LLM_API_KEY", "a")
    monkeypatch.setenv("OPENROUTER_API_KEY", "or")
    assert llm.chat("sys", "usr") == "via openrouter"
    url, kw = calls[0]
    assert url == "https://api.anthropic.com/v1/messages"
    assert kw["headers"]["x-api-key"] == "a" and kw["json"]["system"] == "sys"
    assert calls[1][0] == "https://openrouter.ai/api/v1/chat/completions"


def test_gemini_uses_native_generate_content(monkeypatch):
    seen = {}

    def post(url, **kw):
        seen.update(url=url, **kw)
        return _Resp(True, {"candidates": [{"content": {"parts": [{"text": "native"}]}}],
                            "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 1}})

    monkeypatch.setattr(requests, "post", post)
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("LLM_API_KEY", "k")
    assert llm.chat("sys", "usr") == "native"
    assert seen["url"] == "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent"
    assert seen["headers"] == {"x-goog-api-key": "k"}
    assert seen["json"]["systemInstruction"]["parts"][0]["text"] == "sys"


def test_ollama_call_is_keyless_and_local(monkeypatch):
    seen = {}

    def post(url, **kw):
        seen.update(url=url, **kw)
        return _Resp(True, {"choices": [{"message": {"content": "<think>x</think>local"}}]})

    monkeypatch.setattr(requests, "post", post)
    monkeypatch.setenv("OLLAMA", "yes")
    assert llm.chat("s", "u") == "local"
    assert seen["url"] == "http://localhost:11434/v1/chat/completions" and seen["headers"] == {}


# ── response cache ────────────────────────────────────────────────────────────

def _counting_post(monkeypatch, text="an answer"):
    calls = []

    def post(url, **kw):
        calls.append(kw["json"])
        return _Resp(True, {"choices": [{"message": {"content": text}}]})

    monkeypatch.setattr(requests, "post", post)
    return calls


def test_same_prompt_is_answered_from_the_cache_and_survives_a_restart(monkeypatch):
    calls = _counting_post(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    assert llm.chat("sys", "usr") == "an answer"
    assert llm.chat("sys", "usr") == "an answer"
    assert len(calls) == 1
    llm_cache._STATS.update(hits=0, misses=0)         # a new process: counters reset, file stays
    monkeypatch.delenv("OPENAI_API_KEY")               # ...and no key is needed for a cached answer
    assert llm.chat("sys", "usr") == "an answer" and llm_cache.stats()["hits"] == 1
    assert len(calls) == 1 and llm_cache.stats()["entries"] == 1


def test_any_change_to_prompt_model_or_sampling_is_a_miss(monkeypatch):
    calls = _counting_post(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    llm.chat("sys", "usr")
    llm.chat("sys", "other")
    llm.chat("other", "usr")
    llm.chat("sys", "usr", max_tokens=50)
    monkeypatch.setenv("LLM_MODEL", "another-model")
    llm.chat("sys", "usr")
    assert len(calls) == 5


def test_cache_is_off_for_sampled_calls_when_disabled_and_after_expiry(monkeypatch):
    calls = _counting_post(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    llm.chat("s", "u", temperature=0.7)
    llm.chat("s", "u", temperature=0.7)
    assert len(calls) == 2                             # not deterministic, so never cached
    monkeypatch.setenv("LLM_CACHE", "no")
    llm.chat("s", "u")
    llm.chat("s", "u")
    assert len(calls) == 4 and llm_cache.stats()["entries"] == 0
    monkeypatch.setenv("LLM_CACHE", "yes")
    llm.chat("s", "u")
    monkeypatch.setenv("LLM_CACHE_TTL_SECONDS", "1")
    monkeypatch.setattr(llm_cache.time, "time", lambda t=llm_cache.time.time(): t + 5)
    llm.chat("s", "u")                                 # expired entry is refreshed
    assert len(calls) == 6


def test_failures_and_secrets_are_not_cached(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.setattr(requests, "post", lambda *a, **kw: _Resp(False))
    with pytest.raises(requests.HTTPError):
        llm.chat("s", "u")
    assert llm_cache.stats()["entries"] == 0
    _counting_post(monkeypatch, text="mail bob@corp.com")
    assert llm.chat("s", "u") == "mail [REDACTED:email]"
    assert "bob@corp.com" not in llm_cache.path().read_text()


def test_cache_is_bounded_and_clearable(monkeypatch):
    _counting_post(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.setenv("LLM_CACHE_MAX_ENTRIES", "3")
    for i in range(6):
        llm.chat("s", f"prompt {i}")
    assert llm_cache.stats()["entries"] == 3
    assert llm_cache.clear() == 3 and llm_cache.stats()["entries"] == 0
