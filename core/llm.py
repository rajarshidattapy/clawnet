"""LLM backend — OpenAI, Anthropic, Gemini, OpenRouter, or a local Ollama.

The only place ClawNet talks to a language model. Both the network agent and the
sandbox explainer go through `chat()`; the ClawForge harness reads `resolve()` to
register the same provider in TrueForge. Configuration comes from the environment:

    OLLAMA=yes|no        yes = local model only (no cloud call, no cloud fallback)
    OLLAMA_BASE_URL      default http://localhost:11434
    OLLAMA_MODEL         default llama3.1

    LLM_PROVIDER         openai | anthropic | gemini | openrouter   (default openai)
    LLM_API_KEY          key for that provider
    LLM_MODEL            default per provider (below)
    LLM_FAST_MODEL       model for short, low-cost explanations (defaults to LLM_MODEL)
    LLM_REASONING_MODEL  model for copilot/deeper analysis (defaults to LLM_MODEL)
    LLM_BASE_URL         override the provider endpoint

    OPENAI_API_KEY / ANTHROPIC_API_KEY / GEMINI_API_KEY / OPENROUTER_API_KEY
                         per-provider keys, used when LLM_API_KEY is empty
    OPENAI_MODEL, OPENAI_BASE_URL, OPENROUTER_MODEL (or OPENROUTER_LLM_MODEL),
    OPENROUTER_BASE_URL  per-provider overrides, used when the LLM_* ones are empty
    OPENAI_REASONING_EFFORT  default none (OpenAI reasoning models only)

If the chosen cloud provider fails and OPENROUTER_API_KEY is set, the call is retried
on OpenRouter. With OLLAMA=yes nothing leaves the machine.

Everything the model returns passes through guardrails.redact (secrets and PII).
Answers are cached on disk by prompt hash (llm_cache.py; LLM_CACHE=no turns it off).
Every call is traced with tokens, cost and latency (telemetry.py).

Plain HTTP via `requests` — no vendor SDKs needed.
"""
from __future__ import annotations

import hashlib
import os
import re
import time
from dataclasses import dataclass, replace
from typing import Optional

import requests

try:
    import llm_cache
    import telemetry
    from guardrails import redact_report
except ImportError:
    from core import llm_cache, telemetry  # type: ignore
    from core.guardrails import redact_report  # type: ignore

PROVIDERS = ("openai", "anthropic", "gemini", "openrouter")
ROUTES = ("fast", "reasoning")

# provider -> (base url, default model, per-provider key env)
_DEFAULTS = {
    "openai":     ("https://api.openai.com/v1", "gpt-5.4-mini", "OPENAI_API_KEY"),
    "anthropic":  ("https://api.anthropic.com/v1", "claude-haiku-5-5", "ANTHROPIC_API_KEY"),
    # Gemini's native endpoint. It is more broadly available than its compatibility endpoint.
    "gemini":     ("https://generativelanguage.googleapis.com/v1beta", "gemini-3.6-flash",
                   "GEMINI_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/v1", "openai/gpt-5.4-mini", "OPENROUTER_API_KEY"),
}
_OLLAMA_URL = "http://localhost:11434"
_OLLAMA_MODEL = "llama3.1"
_ANTHROPIC_VERSION = "2023-06-01"

# Reasoning models served through compatible endpoints may wrap their scratchpad
# in <think>…</think>; strip it so callers get just the answer.
_THINK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


@dataclass(frozen=True)
class Provider:
    name: str        # openai | anthropic | gemini | openrouter | ollama
    api_key: str     # empty for ollama
    model: str
    base_url: str    # no trailing slash; for ollama this is the OpenAI-compatible /v1 endpoint

    @property
    def local(self) -> bool:
        return self.name == "ollama"


def _env(*names: str) -> str:
    """First non-empty value among the named environment variables."""
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


def flag(name: str) -> bool:
    return _env(name).lower() in ("1", "true", "yes", "y", "on")


def ollama_enabled() -> bool:
    return flag("OLLAMA")


def _provider(name: str, *, chosen: bool) -> Provider:
    """Settings for one cloud provider. The LLM_* variables only apply to the chosen one."""
    base, default_model, key_env = _DEFAULTS[name]
    generic = lambda var: (var,) if chosen else ()          # noqa: E731
    keys = generic("LLM_API_KEY") + (key_env,) + (("GOOGLE_API_KEY",) if name == "gemini" else ())
    models = generic("LLM_MODEL") + {
        "openai": ("OPENAI_MODEL",),
        "openrouter": ("OPENROUTER_MODEL", "OPENROUTER_LLM_MODEL"),   # the latter is the older .env name
    }.get(name, ())
    urls = generic("LLM_BASE_URL") + {
        "openai": ("OPENAI_BASE_URL",),
        "openrouter": ("OPENROUTER_BASE_URL",),
    }.get(name, ())
    return Provider(name, _env(*keys), _env(*models) or default_model, (_env(*urls) or base).rstrip("/"))


def resolve() -> Provider:
    """The provider this process should use, from the environment."""
    if ollama_enabled():
        url = (_env("OLLAMA_BASE_URL") or _OLLAMA_URL).rstrip("/")
        if not url.endswith("/v1"):
            url += "/v1"
        return Provider("ollama", "", _env("OLLAMA_MODEL") or _OLLAMA_MODEL, url)
    name = (_env("LLM_PROVIDER") or "openai").lower()
    if name not in PROVIDERS:
        raise SystemExit(f"LLM_PROVIDER={name!r} is not supported; use one of: {', '.join(PROVIDERS)}")
    return _provider(name, chosen=True)


def routed(route: Optional[str] = None, model: Optional[str] = None) -> Provider:
    """Resolve a provider for an explicit workload route.

    An explicit ``model`` wins over a route so reproducible callers such as quality
    evaluations can pin their model. Routes never infer intent from prompt content.
    """
    provider = resolve()
    if model:
        return replace(provider, model=model)
    if route is None:
        return provider
    if route not in ROUTES:
        raise ValueError(f"unknown LLM route {route!r}; use one of: {', '.join(ROUTES)}")
    return replace(provider, model=_env(f"LLM_{route.upper()}_MODEL") or provider.model)


def fallback() -> Optional[Provider]:
    """OpenRouter as the cloud fallback, when it is configured and is not already the choice."""
    if ollama_enabled() or resolve().name == "openrouter":
        return None
    other = _provider("openrouter", chosen=False)
    return other if other.api_key else None


def available() -> bool:
    """True when a provider is configured. No network probe — a missing key never stalls a caller."""
    p = resolve()
    return p.local or bool(p.api_key) or fallback() is not None


def _is_reasoning_model(name: str) -> bool:
    # OpenRouter ids carry a vendor prefix ("openai/gpt-5.4-mini").
    return name.lower().rsplit("/", 1)[-1].startswith(("gpt-5", "o1", "o3", "o4"))


def _usage(data: dict) -> dict:
    """Token counts, and the provider's own cost when it sends one (OpenRouter does), from a response."""
    u = data.get("usage") or {}
    count = lambda v: v if isinstance(v, int) and not isinstance(v, bool) else None      # noqa: E731
    cost = u.get("cost")
    return {"input": count(u.get("prompt_tokens", u.get("input_tokens", u.get("promptTokenCount")))),
            "output": count(u.get("completion_tokens", u.get("output_tokens", u.get("candidatesTokenCount")))),
            "cost": float(cost) if isinstance(cost, (int, float)) and not isinstance(cost, bool) else None}


def _complete(p: Provider, system: str, user: str, max_tokens: int,
              temperature: float, timeout: int) -> tuple[str, dict]:
    """(answer, usage) from one provider call."""
    if p.name == "gemini":
        resp = requests.post(
            f"{p.base_url}/models/{p.model}:generateContent", timeout=timeout,
            headers={"x-goog-api-key": p.api_key},
            json={"systemInstruction": {"parts": [{"text": system}]},
                  "contents": [{"role": "user", "parts": [{"text": user}]}],
                  "generationConfig": {"maxOutputTokens": max_tokens, "temperature": temperature}})
        resp.raise_for_status()
        data = resp.json()
        parts = (((data.get("candidates") or [{}])[0].get("content") or {}).get("parts") or [])
        text = "".join(part.get("text", "") for part in parts)
        return _THINK.sub("", text).strip(), _usage({"usage": data.get("usageMetadata") or {}})

    if p.name == "anthropic":
        resp = requests.post(
            p.base_url + "/messages", timeout=timeout,
            headers={"x-api-key": p.api_key, "anthropic-version": _ANTHROPIC_VERSION},
            json={"model": p.model, "max_tokens": max_tokens, "temperature": temperature,
                  "system": system, "messages": [{"role": "user", "content": user}]})
        resp.raise_for_status()
        data = resp.json()
        blocks = data.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        return _THINK.sub("", text).strip(), _usage(data)

    payload = {"model": p.model,
               "messages": [{"role": "system", "content": system},
                            {"role": "user", "content": user}]}
    openai_style = p.name in ("openai", "openrouter")
    payload["max_completion_tokens" if openai_style else "max_tokens"] = max_tokens
    if openai_style and _is_reasoning_model(p.model):
        # Reasoning models reject a custom temperature. ClawNet wants one grounded
        # sentence, not a reasoning trace, so effort defaults to the lowest level.
        payload["reasoning_effort"] = _env("OPENAI_REASONING_EFFORT") or "none"
    else:
        payload["temperature"] = temperature
    if p.name == "openrouter" and not (openai_style and _is_reasoning_model(p.model)) \
            and _env("LLM_REASONING").lower() not in ("on", "yes", "1", "true"):
        # ClawNet asks for one short sentence. A thinking model left on spends the whole token
        # budget thinking and returns nothing. LLM_REASONING=on keeps it, for longer answers.
        payload["reasoning"] = {"enabled": False}
    headers = {"Authorization": f"Bearer {p.api_key}"} if p.api_key else {}
    resp = requests.post(p.base_url + "/chat/completions", json=payload, headers=headers,
                         timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    choices = data.get("choices") or [{}]
    text = ((choices[0].get("message") or {}).get("content")) or ""
    return _THINK.sub("", text).strip(), _usage(data)


def chat(system: str, user: str, *, max_tokens: int = 200,
         temperature: float = 0.0, timeout: int = 60, model: Optional[str] = None,
         route: Optional[str] = None) -> str:
    """One-shot chat completion. Returns the model's text answer, redacted of secrets and PII.

    `model` overrides the model id on the chosen provider (the quality eval uses it to judge
    with a different model than the one being judged).
    `route` is an explicit workload class: ``fast`` for economical short answers or
    ``reasoning`` for deeper copilot analysis. Both fall back to the normal provider model
    unless their corresponding LLM_*_MODEL variable is set.

    temperature defaults to 0 — ClawNet wants the explanation to be as stable as
    the deterministic verdict it narrates. Tries the chosen provider first; if its key is
    missing or the call fails, retries on OpenRouter when that is configured (never in
    OLLAMA mode). Raises when nothing worked so callers can fall back to the rule summary.

    Every call is a "generation" span (core/telemetry.py): model, tokens, cost, latency,
    cache hit, and each provider attempt.
    """
    # Only deterministic calls are cached: at temperature 0 the same prompt means the same answer.
    primary = routed(route, model)
    cacheable = llm_cache.enabled() and temperature == 0
    with telemetry.span("llm.chat", "generation", provider=primary.name, model=primary.model,
                        route=route or "default",
                        max_tokens=max_tokens,
                        prompt_hash=hashlib.sha256(system.encode("utf-8")).hexdigest()[:12]) as sp:
        sp.set_io(input=user)
        if cacheable:
            k = llm_cache.key(primary.name, primary.model, system, user, max_tokens, temperature)
            if (hit := llm_cache.get(k)) is not None:
                sp.set(cached=True).set_io(output=hit)
                sp.set_generation(provider=primary.name, model=primary.model, reported_cost=0.0)
                return hit
        attempts: list[dict] = []
        try:
            raw, used, usage = _chat(primary, system, user, max_tokens, temperature, timeout, attempts)
        finally:
            sp.set(attempts=attempts)
        estimated = usage["input"] is None or usage["output"] is None
        sp.set_generation(
            provider=used.name, model=used.model, estimated=estimated, reported_cost=usage["cost"],
            input_tokens=telemetry.estimate_tokens(system + user) if usage["input"] is None else usage["input"],
            output_tokens=telemetry.estimate_tokens(raw) if usage["output"] is None else usage["output"])
        text, found = redact_report(raw)
        sp.set(fallback=used.name != primary.name, redactions=len(found)).set_io(output=text)
        if cacheable:
            llm_cache.put(k, text)      # the redacted answer, never the raw one
        return text


def _attempt(p: Provider, attempts: list, system: str, user: str, max_tokens: int,
             temperature: float, timeout: int) -> tuple[str, dict]:
    """One provider call, noting its outcome and latency in `attempts`."""
    started = time.time()
    note = {"provider": p.name, "model": p.model}
    attempts.append(note)
    try:
        out = _complete(p, system, user, max_tokens, temperature, timeout)
        note.update(ok=True, ms=round((time.time() - started) * 1000, 1))
        return out
    except (requests.RequestException, ValueError) as exc:
        note.update(ok=False, ms=round((time.time() - started) * 1000, 1), error=f"{type(exc).__name__}: {exc}"[:160])
        raise


def _chat(primary: Provider, system: str, user: str, max_tokens: int, temperature: float,
          timeout: int, attempts: list) -> tuple[str, Provider, dict]:
    """(answer, the provider that answered, its usage); raises when no provider could."""
    backup = fallback()
    if not primary.local and not primary.api_key and backup is None:
        raise RuntimeError(f"no API key for LLM_PROVIDER={primary.name} (set LLM_API_KEY)")
    error: Optional[Exception] = None
    if primary.local or primary.api_key:
        try:
            text, usage = _attempt(primary, attempts, system, user, max_tokens, temperature, timeout)
            return text, primary, usage
        except (requests.RequestException, ValueError) as exc:
            if backup is None:
                raise
            error = exc
    try:
        text, usage = _attempt(backup, attempts, system, user, max_tokens, temperature, timeout)
        return text, backup, usage
    except (requests.RequestException, ValueError) as exc:
        raise exc from error
