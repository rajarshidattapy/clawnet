"""Persistent LLM response cache.

Keyed on a SHA-256 of the prompt as `llm.chat()` receives it (already scrubbed by the
callers: machine strings go through policy.scrub, and the payload is built by
policy.llm_payload) plus the provider, model and sampling settings. The same
evidence therefore costs one model call, across restarts and across the TUI and the MCP
server processes.

Only the hash and the (already redacted) answer are stored, never the prompt. File:
~/.clawnet/llm_cache.json, written atomically.

    LLM_CACHE=yes|no                 default yes
    LLM_CACHE_TTL_SECONDS            default 86400 (24 h); 0 = never expire
    LLM_CACHE_MAX_ENTRIES            default 500 (least recently used are dropped)
    CLAWNET_LLM_CACHE_PATH           default ~/.clawnet/llm_cache.json
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Optional

_DEFAULT_PATH = Path.home() / ".clawnet" / "llm_cache.json"
_LOCK = threading.RLock()
_STATS = {"hits": 0, "misses": 0}


def _env(name: str, default: str) -> str:
    return os.environ.get(name, "").strip() or default


def enabled() -> bool:
    return _env("LLM_CACHE", "yes").lower() in ("1", "true", "yes", "y", "on")


def path() -> Path:
    return Path(_env("CLAWNET_LLM_CACHE_PATH", str(_DEFAULT_PATH)))


def _ttl() -> int:
    try:
        return max(0, int(_env("LLM_CACHE_TTL_SECONDS", "86400")))
    except ValueError:
        return 86400


def _max_entries() -> int:
    try:
        return max(1, int(_env("LLM_CACHE_MAX_ENTRIES", "500")))
    except ValueError:
        return 500


def key(provider: str, model: str, system: str, user: str, max_tokens: int, temperature: float) -> str:
    """The cache key. Any change to the prompt, model or sampling gives a new key."""
    blob = json.dumps([provider, model, system, user, max_tokens, temperature],
                      ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _load() -> dict:
    try:
        data = json.loads(path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _fresh(entry: object, now: float) -> bool:
    if not isinstance(entry, dict) or not isinstance(entry.get("text"), str):
        return False
    ttl = _ttl()
    return ttl == 0 or now - float(entry.get("created", 0)) < ttl


def get(k: str) -> Optional[str]:
    """The cached answer, or None on a miss or an expired entry."""
    with _LOCK:
        entry = _load().get(k)
        if _fresh(entry, time.time()):
            _STATS["hits"] += 1
            return entry["text"]
        _STATS["misses"] += 1
        return None


def put(k: str, text: str) -> None:
    """Store an answer. Re-reads the file first so a second process's entries are kept."""
    if not text:
        return
    with _LOCK:
        now = time.time()
        data = {h: e for h, e in _load().items() if _fresh(e, now)}
        data[k] = {"text": text, "created": now}
        if len(data) > _max_entries():
            # Drop the oldest entries.
            for h in sorted(data, key=lambda h: data[h].get("created", 0))[:len(data) - _max_entries()]:
                del data[h]
        p = path()
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_name(f"{p.name}.{os.getpid()}.tmp")
            tmp.write_text(json.dumps(data), encoding="utf-8")
            os.replace(tmp, p)
        except OSError:
            pass    # a cache that cannot be written is just a cache miss next time


def clear() -> int:
    """Delete every cached answer. Returns how many there were."""
    with _LOCK:
        n = len(_load())
        try:
            path().unlink()
        except OSError:
            pass
        return n


def stats() -> dict:
    """Hit/miss counters for this process and the size of the cache file."""
    with _LOCK:
        now = time.time()
        return {"enabled": enabled(), **_STATS,
                "entries": sum(1 for e in _load().values() if _fresh(e, now)),
                "path": str(path())}
