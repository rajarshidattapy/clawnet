"""LLM backend — the OpenAI Chat Completions API, with an OpenRouter fallback.

The only place ClawNet talks to a language model. Both the network agent and the
sandbox explainer go through `chat()`. Configuration comes from the environment:

    OPENAI_API_KEY   required for AI explanations (verdicts work without it)
    OPENAI_MODEL     default gpt-5.4-mini
    OPENAI_REASONING_EFFORT  default none (reasoning models only)
    OPENAI_BASE_URL  default https://api.openai.com/v1 (any OpenAI-compatible endpoint)

    OPENROUTER_API_KEY   optional; when set, a failed OpenAI call (or a missing OpenAI key)
                         is retried against OpenRouter
    OPENROUTER_MODEL     default openai/gpt-5.4-mini
    OPENROUTER_BASE_URL  default https://openrouter.ai/api/v1

Plain HTTP via `requests` — no openai package needed.
"""
from __future__ import annotations

import os
import re

import requests

_DEFAULT_BASE_URL = "https://api.openai.com/v1"
_DEFAULT_MODEL = "gpt-5.4-mini"
_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
_OPENROUTER_MODEL = "openai/gpt-5.4-mini"

# Reasoning models served through compatible endpoints may wrap their scratchpad
# in <think>…</think>; strip it so callers get just the answer.
_THINK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def base_url() -> str:
    return os.environ.get("OPENAI_BASE_URL", _DEFAULT_BASE_URL).rstrip("/")


def model() -> str:
    return os.environ.get("OPENAI_MODEL", _DEFAULT_MODEL)


def api_key() -> str:
    return os.environ.get("OPENAI_API_KEY", "").strip()


def openrouter_key() -> str:
    return os.environ.get("OPENROUTER_API_KEY", "").strip()


def openrouter_base_url() -> str:
    return os.environ.get("OPENROUTER_BASE_URL", _OPENROUTER_BASE_URL).rstrip("/")


def openrouter_model() -> str:
    return os.environ.get("OPENROUTER_MODEL", _OPENROUTER_MODEL)


def _is_reasoning_model(name: str) -> bool:
    # OpenRouter ids carry a vendor prefix ("openai/gpt-5.4-mini").
    return name.lower().rsplit("/", 1)[-1].startswith(("gpt-5", "o1", "o3", "o4"))


def available() -> bool:
    """True when a key is configured. No network probe — a missing key never stalls a caller."""
    return bool(api_key() or openrouter_key())


def _complete(url: str, key: str, model_id: str, system: str, user: str,
              max_tokens: int, temperature: float, timeout: int) -> str:
    payload = {
        "model": model_id,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_completion_tokens": max_tokens,
    }
    if _is_reasoning_model(model_id):
        # Reasoning models reject a custom temperature. ClawNet wants one grounded
        # sentence, not a reasoning trace, so effort defaults to the lowest level.
        payload["reasoning_effort"] = os.environ.get("OPENAI_REASONING_EFFORT", "none")
    else:
        payload["temperature"] = temperature
    resp = requests.post(url + "/chat/completions", json=payload, timeout=timeout,
                         headers={"Authorization": f"Bearer {key}"})
    resp.raise_for_status()
    choices = resp.json().get("choices") or [{}]
    text = ((choices[0].get("message") or {}).get("content")) or ""
    return _THINK.sub("", text).strip()


def chat(system: str, user: str, *, max_tokens: int = 200,
         temperature: float = 0.0, timeout: int = 60) -> str:
    """One-shot chat completion. Returns the model's text answer.

    temperature defaults to 0 — ClawNet wants the explanation to be as stable as
    the deterministic verdict it narrates. Tries OpenAI first; if that key is missing
    or the call fails, retries on OpenRouter when OPENROUTER_API_KEY is set. Raises
    when nothing worked so callers can fall back to the rule summary.
    """
    key, or_key = api_key(), openrouter_key()
    if not key and not or_key:
        raise RuntimeError("OPENAI_API_KEY is not set")
    error: Exception | None = None
    if key:
        try:
            return _complete(base_url(), key, model(), system, user,
                             max_tokens, temperature, timeout)
        except (requests.RequestException, ValueError) as exc:
            if not or_key:
                raise
            error = exc
    try:
        return _complete(openrouter_base_url(), or_key, openrouter_model(), system, user,
                         max_tokens, temperature, timeout)
    except (requests.RequestException, ValueError) as exc:
        raise exc from error
