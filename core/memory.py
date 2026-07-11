"""SuperMemory — persistent security memory for ClawNet v3.

Primary: Supermemory cloud SDK (SUPERMEMORY_API_KEY)
Fallback: JSON file at ~/.clawnet/memory.json (always works offline)
"""
import json
import os
import threading
import time
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

try:
    from supermemory import Supermemory as _SDK
    _HAS_SDK = True
except ImportError:
    _HAS_SDK = False

_JSON_PATH      = Path.home() / ".clawnet" / "memory.json"
_FLUSH_INTERVAL = 30    # seconds between JSON flushes
_MAX_LOCAL      = 2000  # max entries kept in JSON fallback
_CONTAINER_TAG  = "clawnet-threats"

# ── event helpers ─────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def make_event(
    level: str,
    reason: str,
    action: str,
    process: str,
    remote_ip: str,
    port: int = 0,
    exe: str = "",
    decision: str = "",
) -> dict:
    return {
        "ts":        _now_iso(),
        "level":     level,
        "reason":    reason,
        "action":    action,
        "process":   process,
        "remote_ip": remote_ip,
        "port":      port,
        "exe":       exe,
        "decision":  decision,
    }


def _event_to_text(ev: dict) -> str:
    """Human-readable string stored in Supermemory for semantic search."""
    parts = [f"[{ev['level']}] {ev['process']}"]
    if ev.get("remote_ip"):
        parts.append(f"connected to {ev['remote_ip']}")
    if ev.get("port"):
        parts.append(f"port {ev['port']}")
    if ev.get("reason"):
        parts.append(f"— {ev['reason']}")
    if ev.get("exe"):
        parts.append(f"(exe: {ev['exe']})")
    if ev.get("decision"):
        parts.append(f"| decision: {ev['decision']}")
    parts.append(f"at {ev.get('ts', '?')}")
    return " ".join(parts)


# ── SuperMemory class ─────────────────────────────────────────────────────────

class SuperMemory:
    """Stores and retrieves threat events.

    Uses Supermemory SDK when SUPERMEMORY_API_KEY is set; falls back to a
    local JSON file at ~/.clawnet/memory.json otherwise.
    """

    def __init__(self, json_path: Optional[Path] = None) -> None:
        self._path   = json_path or _JSON_PATH
        self._local: deque = deque(maxlen=_MAX_LOCAL)
        self._lock   = threading.Lock()
        self._dirty  = False

        self._client = None
        api_key = os.environ.get("SUPERMEMORY_API_KEY", "")
        if _HAS_SDK and api_key:
            try:
                self._client = _SDK(api_key=api_key)
            except Exception:
                self._client = None

        # always load JSON (used as fallback + for risk_history_lookup speed)
        self._load_json()

        threading.Thread(target=self._flush_loop, daemon=True, name="mem-flush").start()

    @property
    def backend(self) -> str:
        return "supermemory" if self._client else "json"

    # ── public API ────────────────────────────────────────────────────────────

    def store_event(self, event: dict) -> None:
        """Record a threat event to Supermemory (cloud) and local JSON cache."""
        with self._lock:
            self._local.appendleft(event)
            self._dirty = True

        if self._client:
            threading.Thread(
                target=self._cloud_add,
                args=(event,),
                daemon=True,
            ).start()

    def retrieve_events(
        self,
        ip: str = "",
        process: str = "",
        port: int = 0,
        days: int = 7,
        limit: int = 10,
    ) -> list[dict]:
        """Return recent matching events.

        Uses Supermemory semantic search when available; otherwise scans local
        JSON cache.
        """
        if self._client and (ip or process or port):
            try:
                return self._cloud_search(ip=ip, process=process, port=port, limit=limit)
            except Exception:
                pass
        return self._local_search(ip=ip, process=process, port=port, days=days, limit=limit)

    def risk_history_lookup(self, ip: str = "", process: str = "") -> dict:
        """Concise risk summary: hit count and worst level seen."""
        events = self.retrieve_events(ip=ip, process=process, days=30, limit=50)
        if not events:
            return {}
        levels = [e.get("level", "?") for e in events]
        worst  = ("CRITICAL"   if "CRITICAL"   in levels else
                  "SUSPICIOUS" if "SUSPICIOUS" in levels else levels[0])
        return {
            "hits":        len(events),
            "worst":       worst,
            "last_ts":     events[0].get("ts", ""),
            "last_reason": events[0].get("reason", ""),
        }

    def prior_decision_lookup(self, ip: str = "", process: str = "") -> Optional[str]:
        """Return the last user decision recorded for this target."""
        events = self.retrieve_events(ip=ip, process=process, days=90, limit=20)
        for ev in events:
            if ev.get("decision"):
                return ev["decision"]
        return None

    def build_context(self, ip: str = "", process: str = "", port: int = 0) -> str:
        """Short memory context string injected into AI prompts."""
        hist = self.risk_history_lookup(ip=ip, process=process)
        if not hist:
            return ""
        lines = [f"[MEMORY] Seen {hist['hits']}x in last 30 days, worst={hist['worst']}"]
        if hist.get("last_reason"):
            lines.append(f"[MEMORY] Last flag: {hist['last_reason']}")
        decision = self.prior_decision_lookup(ip=ip, process=process)
        if decision:
            lines.append(f"[MEMORY] Prior decision: {decision}")
        return "\n".join(lines)

    # ── Supermemory cloud helpers ─────────────────────────────────────────────

    def _cloud_add(self, event: dict) -> None:
        try:
            self._client.add(
                content=_event_to_text(event),
                container_tags=[_CONTAINER_TAG],
                metadata={
                    "level":     event.get("level", ""),
                    "process":   event.get("process", ""),
                    "remote_ip": event.get("remote_ip", ""),
                    "port":      str(event.get("port", "")),
                    "ts":        event.get("ts", ""),
                },
            )
        except Exception:
            pass

    def _cloud_search(
        self, ip: str, process: str, port: int, limit: int
    ) -> list[dict]:
        query_parts = []
        if process:
            query_parts.append(process)
        if ip:
            query_parts.append(ip)
        if port:
            query_parts.append(f"port {port}")
        query = " ".join(query_parts) or "threat"

        resp = self._client.search.documents(
            q=query,
            container_tags=[_CONTAINER_TAG],
            limit=limit,
        )
        events = []
        for result in (resp.results or []):
            ev = self._result_to_event(result)
            if ev:
                events.append(ev)
        return events

    @staticmethod
    def _result_to_event(result) -> Optional[dict]:
        """Convert a Supermemory search result back to an event dict."""
        meta = result.metadata or {}
        content = result.content or (
            result.chunks[0].content if result.chunks else ""
        )
        return {
            "ts":        meta.get("ts", ""),
            "level":     meta.get("level", "?"),
            "reason":    content[:120],
            "action":    "",
            "process":   meta.get("process", ""),
            "remote_ip": meta.get("remote_ip", ""),
            "port":      int(meta.get("port", 0) or 0),
            "exe":       "",
            "decision":  "",
        }

    # ── local JSON helpers ────────────────────────────────────────────────────

    def _local_search(
        self, ip: str, process: str, port: int, days: int, limit: int
    ) -> list[dict]:
        cutoff  = (datetime.utcnow() - timedelta(days=days)).isoformat()
        results = []
        with self._lock:
            for ev in self._local:
                if ev.get("ts", "") < cutoff:
                    continue
                match = (
                    (ip      and ev.get("remote_ip") == ip) or
                    (process and process.lower() in ev.get("process", "").lower()) or
                    (port    and ev.get("port") == port)
                )
                if match:
                    results.append(ev)
                    if len(results) >= limit:
                        break
        return results

    def _load_json(self) -> None:
        try:
            if self._path.exists():
                with open(self._path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for ev in reversed(data):
                    self._local.appendleft(ev)
        except Exception:
            pass

    def _flush_json(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(list(self._local), f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _flush_loop(self) -> None:
        while True:
            time.sleep(_FLUSH_INTERVAL)
            with self._lock:
                dirty, self._dirty = self._dirty, False
            if dirty:
                self._flush_json()
