"""Offline checks for provider selection, the Ollama switch and the OpenRouter fallback."""
import sys
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
import llm  # noqa: E402

_VARS = ("OLLAMA", "OLLAMA_BASE_URL", "OLLAMA_MODEL", "LLM_PROVIDER", "LLM_API_KEY", "LLM_MODEL",
         "LLM_BASE_URL", "OPENAI_API_KEY", "OPENAI_MODEL", "OPENAI_BASE_URL", "ANTHROPIC_API_KEY",
         "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENROUTER_API_KEY", "OPENROUTER_MODEL",
         "OPENROUTER_LLM_MODEL", "OPENROUTER_BASE_URL")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for v in _VARS:
        monkeypatch.delenv(v, raising=False)


def test_default_is_openai_and_legacy_key_still_works(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-legacy")
    p = llm.resolve()
    assert (p.name, p.api_key, p.model) == ("openai", "sk-legacy", "gpt-5.4-mini")


@pytest.mark.parametrize("name,model,url", [
    ("openai", "gpt-5.4-mini", "https://api.openai.com/v1"),
    ("anthropic", "claude-haiku-5-5", "https://api.anthropic.com/v1"),
    ("gemini", "gemini-2.5-flash", "https://generativelanguage.googleapis.com/v1beta/openai"),
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


def test_ollama_call_is_keyless_and_local(monkeypatch):
    seen = {}

    def post(url, **kw):
        seen.update(url=url, **kw)
        return _Resp(True, {"choices": [{"message": {"content": "<think>x</think>local"}}]})

    monkeypatch.setattr(requests, "post", post)
    monkeypatch.setenv("OLLAMA", "yes")
    assert llm.chat("s", "u") == "local"
    assert seen["url"] == "http://localhost:11434/v1/chat/completions" and seen["headers"] == {}
