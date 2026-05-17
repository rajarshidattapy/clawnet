"""Shared audit log writer used by all pipeline nodes."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from core.k8agent.src.models import LogEntry

logger = logging.getLogger(__name__)

# Anchor to project root so the path works regardless of cwd
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
AUDIT_LOG_PATH = _PROJECT_ROOT / "data" / "audit_log.json"


def write_audit_entry(entry: LogEntry) -> None:
    """Append a LogEntry to the shared audit log JSON file."""
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    existing: list[dict] = []
    if AUDIT_LOG_PATH.exists():
        try:
            raw = AUDIT_LOG_PATH.read_text()
            if raw.strip():
                existing = json.loads(raw)
        except (json.JSONDecodeError, OSError):
            logger.warning("Could not read existing audit log; starting fresh")

    existing.append(dict(entry))

    try:
        AUDIT_LOG_PATH.write_text(json.dumps(existing, indent=2, default=str))
    except OSError:
        logger.exception("Failed to write audit log")


def make_entry(
    incident_id: str,
    stage: str,
    summary: str,
    details: dict | None = None,
    decision: str = "",
    outcome: str = "",
) -> LogEntry:
    """Build a LogEntry with the current UTC timestamp."""
    return LogEntry(
        incident_id=incident_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        stage=stage,
        summary=summary,
        details=details or {},
        decision=decision,
        outcome=outcome,
    )
