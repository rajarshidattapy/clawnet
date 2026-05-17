"""LLM call tracing — captures every LLM call with timing, tokens, and previews."""

import json
import time
import threading
from pathlib import Path
from datetime import datetime, timezone

_TRACES_PATH = Path("data/traces.json")
_lock = threading.Lock()


def record_trace(
    *,
    trace_id: str,
    stage: str,
    model: str,
    input_text: str,
    output_text: str,
    duration_ms: int,
) -> None:
    """Append a trace entry to the traces file."""
    entry = {
        "trace_id": trace_id,
        "stage": stage,
        "model": model,
        "input_preview": input_text[:500],
        "output_preview": output_text[:500],
        "input_full": input_text[:5000],
        "output_full": output_text[:5000],
        "input_chars": len(input_text),
        "output_chars": len(output_text),
        "duration_ms": duration_ms,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    with _lock:
        _TRACES_PATH.parent.mkdir(parents=True, exist_ok=True)
        traces = json.loads(_TRACES_PATH.read_text()) if _TRACES_PATH.exists() else []
        traces.append(entry)
        _TRACES_PATH.write_text(json.dumps(traces, indent=2))


def get_traces(limit: int = 100) -> list[dict]:
    """Return the most recent *limit* traces."""
    if not _TRACES_PATH.exists():
        return []
    traces = json.loads(_TRACES_PATH.read_text())
    return traces[-limit:]


def get_traces_for_incident(trace_id: str) -> list[dict]:
    """Return all traces linked to *trace_id* (incident_id)."""
    if not _TRACES_PATH.exists():
        return []
    return [t for t in json.loads(_TRACES_PATH.read_text()) if t["trace_id"] == trace_id]
