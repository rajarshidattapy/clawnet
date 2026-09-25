"""LLM backend — the OpenAI Chat Completions API.

The only place ClawNet talks to a language model. Both the network agent and the
sandbox explainer go through `chat()`. Configuration comes from the environment:

    OPENAI_API_KEY   required for AI explanations (verdicts work without it)
    OPENAI_MODEL     default gpt-5.4-mini
    OPENAI_REASONING_EFFORT  default none (reasoning models only)
    OPENAI_BASE_URL  default https://api.openai.com/v1 (any OpenAI-compatible endpoint)

Stdlib only (urllib) — no openai package needed.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request

_DEFAULT_BASE_URL = "https://api.openai.com/v1"
_DEFAULT_MODEL = "gpt-5.4-mini"

# Reasoning models served through compatible endpoints may wrap their scratchpad
# in <think>…</think>; strip it so callers get just the answer.
_THINK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def base_url() -> str:
    return os.environ.get("OPENAI_BASE_URL", _DEFAULT_BASE_URL).rstrip("/")


def model() -> str:
    return os.environ.get("OPENAI_MODEL", _DEFAULT_MODEL)


def api_key() -> str:
    return os.environ.get("OPENAI_API_KEY", "").strip()


def _is_reasoning_model(name: str) -> bool:
    return name.lower().startswith(("gpt-5", "o1", "o3", "o4"))


def available() -> bool:
    """True when a key is configured. No network probe — a missing key never stalls a caller."""
    return bool(api_key())


def chat(system: str, user: str, *, max_tokens: int = 200,
         temperature: float = 0.0, timeout: int = 60) -> str:
    """One-shot chat completion. Returns the model's text answer.

    temperature defaults to 0 — ClawNet wants the explanation to be as stable as
    the deterministic verdict it narrates. Raises on transport failure so callers
    can fall back to the rule summary.
    """
    key = api_key()
    if not key:
        raise RuntimeError("OPENAI_API_KEY is not set")
    payload = {
        "model": model(),
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_completion_tokens": max_tokens,
    }
    if _is_reasoning_model(payload["model"]):
        # Reasoning models reject a custom temperature. ClawNet wants one grounded
        # sentence, not a reasoning trace, so effort defaults to the lowest level.
        payload["reasoning_effort"] = os.environ.get("OPENAI_REASONING_EFFORT", "none")
    else:
        payload["temperature"] = temperature
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        base_url() + "/chat/completions", data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    choices = data.get("choices") or [{}]
    text = ((choices[0].get("message") or {}).get("content")) or ""
    return _THINK.sub("", text).strip()
