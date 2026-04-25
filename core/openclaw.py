"""OpenClaw — AI intelligence engine for ClawNet. Powered by GPT-4o-mini."""
import json
import os
import queue
import threading
from dataclasses import dataclass
from typing import Optional

try:
    import openai as _openai
    _HAS_OPENAI = True
except ImportError:
    _HAS_OPENAI = False

_MODEL = "gpt-4o-mini"

_SYSTEM_ANALYZE = """\
You are OpenClaw, an embedded AI security analyst in ClawNet (Windows network monitor).
Analyze network connections for threats. Be concise.
Respond ONLY with valid JSON — no prose, no markdown fences.

Format:
{"level": "SAFE"|"SUSPICIOUS"|"CRITICAL", "reason": "<one sentence, max 15 words>", "action": "none"|"monitor"|"kill_process"|"block_ip"|"kill_and_block"}

Focus on: processes running from temp/download paths, C2 beaconing patterns, connections to
high-risk foreign ASNs, high-risk ports (Telnet/RDP/raw DB), unsigned or anomalous binaries.\
"""

_SYSTEM_COPILOT = """\
You are OpenClaw, an AI security analyst in ClawNet (Windows network monitor).
You are in Security Copilot mode. Answer the user's security question concisely and technically,
based on the provided network context. Plain English — no JSON.\
"""


@dataclass
class Analysis:
    level:   str  = "?"
    reason:  str  = ""
    action:  str  = "none"
    process: str  = ""
    remote:  str  = ""
    pid:     Optional[int] = None
    pending: bool = False


class OpenClaw:
    def __init__(self) -> None:
        key = os.environ.get("OPENAI_API_KEY", "")
        self._ok   = _HAS_OPENAI and bool(key)
        self._cache: dict[tuple, Analysis] = {}
        self._lock  = threading.Lock()
        self._q: queue.Queue = queue.Queue(maxsize=30)
        if self._ok:
            self._client = _openai.OpenAI(api_key=key)
            threading.Thread(target=self._worker, daemon=True).start()

    @property
    def available(self) -> bool:
        return self._ok

    # ── public API ────────────────────────────────────────────────────────────

    def request(self, key: tuple, info: dict) -> None:
        """Queue a connection for AI analysis (no-op if already cached)."""
        with self._lock:
            if key in self._cache:
                return
            self._cache[key] = Analysis(
                pending=True,
                reason="Analyzing...",
                process=info.get("process", "?"),
                remote=info.get("remote", ""),
                pid=info.get("pid"),
            )
        try:
            self._q.put_nowait((key, info))
        except queue.Full:
            pass

    def get(self, key: tuple) -> Optional[Analysis]:
        with self._lock:
            return self._cache.get(key)

    def evict(self, active: set) -> None:
        """Remove analyses for connections that are no longer active."""
        with self._lock:
            for k in [k for k in self._cache if k not in active]:
                del self._cache[k]

    def all_analyses(self) -> list[Analysis]:
        with self._lock:
            return list(self._cache.values())

    def copilot(self, question: str, context: str) -> str:
        if not self._ok:
            return "OpenClaw unavailable — set OPENAI_API_KEY to enable AI features."
        r = self._client.chat.completions.create(
            model=_MODEL,
            max_tokens=600,
            messages=[
                {"role": "system", "content": _SYSTEM_COPILOT},
                {"role": "user",   "content": f"Network context:\n{context}\n\nQuestion: {question}"},
            ],
        )
        return r.choices[0].message.content.strip()

    # ── internals ─────────────────────────────────────────────────────────────

    def _worker(self) -> None:
        while True:
            key, info = self._q.get()
            try:
                result = self._call(info)
            except Exception as exc:
                result = Analysis(
                    level="?", reason=str(exc)[:60], action="none",
                    process=info.get("process", "?"),
                    remote=info.get("remote", ""),
                    pid=info.get("pid"),
                )
            with self._lock:
                self._cache[key] = result

    def _call(self, info: dict) -> Analysis:
        prompt = (
            f"Process: {info.get('process')} | Path: {info.get('exe', 'unknown')}\n"
            f"Proto: {info.get('proto')} | Status: {info.get('status')}\n"
            f"Local: {info.get('local')} | Remote: {info.get('remote')}:{info.get('rport', '?')}\n"
            f"Country: {info.get('country', '?')} | Suspicious path: {info.get('suspicious')}\n"
            f"Heuristic risk: {info.get('risk')}"
        )
        r = self._client.chat.completions.create(
            model=_MODEL,
            max_tokens=150,
            messages=[
                {"role": "system", "content": _SYSTEM_ANALYZE},
                {"role": "user",   "content": prompt},
            ],
        )
        text = r.choices[0].message.content.strip()
        s, e = text.find("{"), text.rfind("}") + 1
        if s >= 0 and e > s:
            d = json.loads(text[s:e])
            return Analysis(
                level=d.get("level", "?"),
                reason=d.get("reason", ""),
                action=d.get("action", "none"),
                process=info.get("process", "?"),
                remote=info.get("remote", ""),
                pid=info.get("pid"),
            )
        return Analysis(
            level="?", reason=text[:80], action="none",
            process=info.get("process", "?"),
            remote=info.get("remote", ""),
            pid=info.get("pid"),
        )
