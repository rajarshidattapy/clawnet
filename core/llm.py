"""LLM backend — a local Ollama server. No API keys, no cloud.

The only place ClawNet talks to a language model. Both the network agent and the
sandbox explainer go through `chat()`. Host and model come from the environment:

    OLLAMA_HOST   default http://localhost:11434
    OLLAMA_MODEL  default qwen3:8b

Stdlib only (urllib) — Ollama's native /api/chat endpoint, so there's no OpenAI
package or key to install.
"""
from __future__ import annotations

import json
import os
import re
import socket
import urllib.request
from urllib.parse import urlparse

_DEFAULT_HOST = "http://localhost:11434"
_DEFAULT_MODEL = "qwen3:8b"

# qwen3 and other reasoning models wrap their scratchpad in <think>…</think>;
# strip it so callers get just the answer.
_THINK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def host() -> str:
    return os.environ.get("OLLAMA_HOST", _DEFAULT_HOST).rstrip("/")


def model() -> str:
    return os.environ.get("OLLAMA_MODEL", _DEFAULT_MODEL)


def available(timeout: float = 0.5) -> bool:
    """Cheap TCP probe of the Ollama server, so a down server never stalls a caller."""
    parsed = urlparse(host())
    try:
        socket.create_connection((parsed.hostname or "localhost", parsed.port or 11434),
                                 timeout=timeout).close()
        return True
    except Exception:
        return False


def chat(system: str, user: str, *, max_tokens: int = 200,
         temperature: float = 0.0, timeout: int = 60) -> str:
    """One-shot chat completion against Ollama. Returns the model's text answer.

    temperature defaults to 0 — ClawNet wants the explanation to be as stable as
    the deterministic verdict it narrates. Raises on transport failure so callers
    can fall back to the rule summary.
    """
    body = json.dumps({
        "model": model(),
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        # ClawNet wants one grounded sentence, not a reasoning trace. Disabling
        # thinking on hybrid models (qwen3, …) makes them answer directly instead
        # of burning the token budget in <think> and returning nothing.
        "think": False,
        "options": {"temperature": temperature, "num_predict": max_tokens},
    }).encode("utf-8")
    req = urllib.request.Request(
        host() + "/api/chat", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    text = (data.get("message") or {}).get("content", "")
    return _THINK.sub("", text).strip()
