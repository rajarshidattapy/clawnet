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
    LLM_BASE_URL         override the provider endpoint

    OPENAI_API_KEY / ANTHROPIC_API_KEY / GEMINI_API_KEY / OPENROUTER_API_KEY
                         per-provider keys, used when LLM_API_KEY is empty
    OPENAI_MODEL, OPENAI_BASE_URL, OPENROUTER_MODEL (or OPENROUTER_LLM_MODEL),
    OPENROUTER_BASE_URL  per-provider overrides, used when the LLM_* ones are empty
    OPENAI_REASONING_EFFORT  default none (OpenAI reasoning models only)

If the chosen cloud provider fails and OPENROUTER_API_KEY is set, the call is retried
on OpenRouter. With OLLAMA=yes nothing leaves the machine.

Plain HTTP via `requests` — no vendor SDKs needed.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional

import requests

PROVIDERS = ("openai", "anthropic", "gemini", "openrouter")

# provider -> (base url, default model, per-provider key env)
_DEFAULTS = {
    "openai":     ("https://api.openai.com/v1", "gpt-5.4-mini", "OPENAI_API_KEY"),
    "anthropic":  ("https://api.anthropic.com/v1", "claude-haiku-5-5", "ANTHROPIC_API_KEY"),
    # Gemini's OpenAI-compatible endpoint, so one request shape serves it too.
    "gemini":     ("https://generativelanguage.googleapis.com/v1beta/openai", "gemini-2.5-flash",
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


def _complete(p: Provider, system: str, user: str, max_tokens: int,
              temperature: float, timeout: int) -> str:
    if p.name == "anthropic":
        resp = requests.post(
            p.base_url + "/messages", timeout=timeout,
            headers={"x-api-key": p.api_key, "anthropic-version": _ANTHROPIC_VERSION},
            json={"model": p.model, "max_tokens": max_tokens, "temperature": temperature,
                  "system": system, "messages": [{"role": "user", "content": user}]})
        resp.raise_for_status()
        blocks = resp.json().get("content") or []
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        return _THINK.sub("", text).strip()

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
    headers = {"Authorization": f"Bearer {p.api_key}"} if p.api_key else {}
    resp = requests.post(p.base_url + "/chat/completions", json=payload, headers=headers,
                         timeout=timeout)
    resp.raise_for_status()
    choices = resp.json().get("choices") or [{}]
    text = ((choices[0].get("message") or {}).get("content")) or ""
    return _THINK.sub("", text).strip()


def chat(system: str, user: str, *, max_tokens: int = 200,
         temperature: float = 0.0, timeout: int = 60) -> str:
    """One-shot chat completion. Returns the model's text answer.

    temperature defaults to 0 — ClawNet wants the explanation to be as stable as
    the deterministic verdict it narrates. Tries the chosen provider first; if its key is
    missing or the call fails, retries on OpenRouter when that is configured (never in
    OLLAMA mode). Raises when nothing worked so callers can fall back to the rule summary.
    """
    primary, backup = resolve(), fallback()
    if not primary.local and not primary.api_key and backup is None:
        raise RuntimeError(f"no API key for LLM_PROVIDER={primary.name} (set LLM_API_KEY)")
    error: Optional[Exception] = None
    if primary.local or primary.api_key:
        try:
            return _complete(primary, system, user, max_tokens, temperature, timeout)
        except (requests.RequestException, ValueError) as exc:
            if backup is None:
                raise
            error = exc
    try:
        return _complete(backup, system, user, max_tokens, temperature, timeout)
    except (requests.RequestException, ValueError) as exc:
        raise exc from error
