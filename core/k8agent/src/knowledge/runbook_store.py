"""Self-evolving runbook store backed by a JSON file.

Every resolved incident is recorded as a runbook entry keyed by its
fingerprint.  On subsequent incidents with the same fingerprint the cached
diagnosis and remediation are returned instantly, bypassing the LLM
pipeline entirely.

Thread safety is guaranteed by a :class:`threading.Lock` around all file
I/O operations.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Storage path ──────────────────────────────────────────────────────────

RUNBOOK_DB: Path = Path("data/runbooks.json")

# ── Thread lock ───────────────────────────────────────────────────────────

_lock = threading.Lock()

# ── Internal helpers ──────────────────────────────────────────────────────


def _ensure_db() -> None:
    """Create the database file and parent directories if they don't exist."""
    RUNBOOK_DB.parent.mkdir(parents=True, exist_ok=True)
    if not RUNBOOK_DB.exists():
        RUNBOOK_DB.write_text("{}", encoding="utf-8")


def _read_db() -> dict:
    """Read and return the full runbook database."""
    _ensure_db()
    try:
        text = RUNBOOK_DB.read_text(encoding="utf-8")
        return json.loads(text) if text.strip() else {}
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Failed to read runbook DB: %s", exc)
        return {}


def _write_db(db: dict) -> None:
    """Write the runbook database back to disk."""
    _ensure_db()
    RUNBOOK_DB.write_text(
        json.dumps(db, indent=2, default=str),
        encoding="utf-8",
    )


# ── Public API ────────────────────────────────────────────────────────────


def store_runbook(
    fingerprint: str,
    diagnosis: str,
    remediation: str,
    success: bool,
    resolution_time_ms: int,
) -> None:
    """Record a resolved incident in the runbook store.

    If a runbook for *fingerprint* already exists, it is updated in-place:
    ``hit_count`` is incremented and ``last_used`` is refreshed.  On first
    creation ``hit_count`` starts at 1.
    """
    now = datetime.now(timezone.utc).isoformat()

    with _lock:
        db = _read_db()

        existing = db.get(fingerprint)
        if existing:
            existing["diagnosis"] = diagnosis
            existing["remediation"] = remediation
            existing["success"] = success
            existing["resolution_time_ms"] = resolution_time_ms
            existing["hit_count"] = existing.get("hit_count", 1) + 1
            existing["last_used"] = now
        else:
            db[fingerprint] = {
                "diagnosis": diagnosis,
                "remediation": remediation,
                "success": success,
                "resolution_time_ms": resolution_time_ms,
                "hit_count": 1,
                "last_used": now,
                "created_at": now,
            }

        _write_db(db)

    logger.info(
        "Stored runbook for fingerprint %s (success=%s, resolution=%dms)",
        fingerprint,
        success,
        resolution_time_ms,
    )


def lookup_runbook(fingerprint: str) -> Optional[dict]:
    """Look up a cached runbook by *fingerprint*.

    Returns the runbook entry dict if a **successful** entry exists, or
    ``None`` otherwise.  Also bumps ``hit_count`` and ``last_used`` on hit.
    """
    with _lock:
        db = _read_db()
        entry = db.get(fingerprint)

        if entry is None or not entry.get("success"):
            return None

        # Record the cache hit
        entry["hit_count"] = entry.get("hit_count", 1) + 1
        entry["last_used"] = datetime.now(timezone.utc).isoformat()
        _write_db(db)

    return entry


def get_all_runbooks() -> dict:
    """Return the entire runbook database as a dict keyed by fingerprint."""
    with _lock:
        return _read_db()


def get_runbook_stats() -> dict:
    """Return aggregate statistics about the runbook store.

    Keys returned:
        - ``total_runbooks``: number of stored entries.
        - ``total_hits``: sum of all ``hit_count`` values.
        - ``avg_resolution_time_ms``: mean resolution time across entries.
        - ``cache_hit_rate``: fraction of entries with ``hit_count > 1``
          (i.e. entries that have been reused at least once).
    """
    with _lock:
        db = _read_db()

    if not db:
        return {
            "total_runbooks": 0,
            "total_hits": 0,
            "avg_resolution_time_ms": 0.0,
            "cache_hit_rate": 0.0,
        }

    entries = list(db.values())
    total_runbooks = len(entries)
    total_hits = sum(e.get("hit_count", 0) for e in entries)

    resolution_times = [
        e["resolution_time_ms"]
        for e in entries
        if "resolution_time_ms" in e
    ]
    avg_resolution = (
        sum(resolution_times) / len(resolution_times) if resolution_times else 0.0
    )

    reused = sum(1 for e in entries if e.get("hit_count", 0) > 1)
    cache_hit_rate = reused / total_runbooks if total_runbooks else 0.0

    return {
        "total_runbooks": total_runbooks,
        "total_hits": total_hits,
        "avg_resolution_time_ms": round(avg_resolution, 1),
        "cache_hit_rate": round(cache_hit_rate, 3),
    }
