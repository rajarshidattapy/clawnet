"""Skill: diagnose CrashLoopBackOff for a Kubernetes pod.

Fetches previous container logs, pod events, and exit codes to produce a
structured root-cause classification.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from core.k8agent.src.skills.registry import skills_registry
from core.k8agent.src.utils.k8s_client import get_core_v1

logger = logging.getLogger(__name__)

# ── Exit code classification ──────────────────────────────────────────────

_EXIT_CODE_MAP: dict[int, str] = {
    0: "clean_exit",
    1: "application_error",
    2: "shell_misuse",
    126: "permission_denied",
    127: "command_not_found",
    137: "oom_killed_or_sigkill",
    139: "segfault",
    143: "sigterm",
}


def _classify_exit_code(code: int) -> str:
    return _EXIT_CODE_MAP.get(code, f"unknown_exit_{code}")


# ── Skill implementation ─────────────────────────────────────────────────


@skills_registry.skill(
    name="diagnose_crashloop",
    description=(
        "Diagnose a CrashLoopBackOff pod by inspecting previous container "
        "logs, events, and exit codes.  Returns a structured diagnosis."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "pod_name": {"type": "string", "description": "Name of the pod"},
            "namespace": {"type": "string", "description": "Kubernetes namespace"},
        },
        "required": ["pod_name", "namespace"],
    },
    output_schema={
        "type": "object",
        "properties": {
            "pod": {"type": "string"},
            "namespace": {"type": "string"},
            "classification": {"type": "string"},
            "exit_code": {"type": "integer"},
            "restart_count": {"type": "integer"},
            "previous_logs_tail": {"type": "string"},
            "events": {"type": "array"},
            "diagnosis": {"type": "string"},
            "assessed_at": {"type": "string"},
        },
    },
)
async def diagnose_crashloop(pod_name: str, namespace: str) -> dict:
    """Diagnose a CrashLoopBackOff pod.

    Gathers evidence from the Kubernetes API and returns a structured
    diagnosis dict with classification, logs, events, and a human-readable
    summary.
    """
    core = get_core_v1()

    # ── 1. Read pod status ────────────────────────────────────────────
    try:
        pod = core.read_namespaced_pod(name=pod_name, namespace=namespace)
    except Exception as exc:
        return {
            "pod": pod_name,
            "namespace": namespace,
            "error": f"Failed to read pod: {exc}",
        }

    # ── 2. Extract exit code and restart count ────────────────────────
    exit_code: int | None = None
    restart_count = 0
    container_name = ""

    for cs in pod.status.container_statuses or []:
        restart_count += cs.restart_count or 0
        container_name = container_name or cs.name

        # Check last terminated state for exit code
        if cs.last_state and cs.last_state.terminated:
            exit_code = cs.last_state.terminated.exit_code
        elif cs.state and cs.state.terminated:
            exit_code = cs.state.terminated.exit_code

    classification = _classify_exit_code(exit_code) if exit_code is not None else "unknown"

    # ── 3. Fetch previous container logs ──────────────────────────────
    previous_logs = ""
    if container_name:
        try:
            previous_logs = core.read_namespaced_pod_log(
                name=pod_name,
                namespace=namespace,
                container=container_name,
                previous=True,
                tail_lines=50,
            )
        except Exception as exc:
            logger.debug(
                "Could not fetch previous logs for %s/%s: %s",
                namespace,
                pod_name,
                exc,
            )

    # ── 4. Fetch relevant events ──────────────────────────────────────
    event_summaries: list[dict] = []
    try:
        events = core.list_namespaced_event(
            namespace=namespace,
            field_selector=f"involvedObject.name={pod_name}",
        )
        for ev in events.items:
            event_summaries.append({
                "reason": ev.reason,
                "message": ev.message,
                "count": ev.count,
                "first_seen": ev.first_timestamp.isoformat() if ev.first_timestamp else None,
                "last_seen": ev.last_timestamp.isoformat() if ev.last_timestamp else None,
            })
    except Exception as exc:
        logger.debug("Could not fetch events for %s/%s: %s", namespace, pod_name, exc)

    # ── 5. Build human-readable diagnosis ─────────────────────────────
    diagnosis_lines = [
        f"Pod {pod_name} in namespace {namespace} is in CrashLoopBackOff.",
        f"Restart count: {restart_count}.",
    ]

    if exit_code is not None:
        diagnosis_lines.append(
            f"Last exit code: {exit_code} ({classification})."
        )

    if classification == "oom_killed_or_sigkill":
        diagnosis_lines.append(
            "The container was killed with SIGKILL (exit 137), likely OOM-killed. "
            "Consider increasing memory limits or investigating memory leaks."
        )
    elif classification == "application_error":
        diagnosis_lines.append(
            "The application exited with code 1 indicating an unhandled error. "
            "Review the previous container logs below for stack traces."
        )
    elif classification == "sigterm":
        diagnosis_lines.append(
            "The container received SIGTERM (exit 143). This may indicate "
            "a liveness probe failure or a graceful shutdown that did not "
            "complete within the termination grace period."
        )
    elif classification == "command_not_found":
        diagnosis_lines.append(
            "The entrypoint command was not found (exit 127). Check the "
            "container image and command specification."
        )

    return {
        "pod": pod_name,
        "namespace": namespace,
        "classification": classification,
        "exit_code": exit_code,
        "restart_count": restart_count,
        "previous_logs_tail": previous_logs[-2000:] if previous_logs else "",
        "events": event_summaries,
        "diagnosis": " ".join(diagnosis_lines),
        "assessed_at": datetime.now(timezone.utc).isoformat(),
    }
