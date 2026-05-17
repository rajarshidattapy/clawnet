"""Skill: diagnose OOMKilled pods.

Reads resource limits, describes the pod, and checks current memory usage
against Prometheus to produce a diagnosis with recommended limits.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

from core.k8agent.src.config import settings
from core.k8agent.src.skills.registry import skills_registry
from core.k8agent.src.utils.k8s_client import get_core_v1

logger = logging.getLogger(__name__)

_BYTES_PER_MB = 1024 * 1024


@skills_registry.skill(
    name="diagnose_oomkill",
    description=(
        "Diagnose an OOMKilled pod by inspecting resource limits, current "
        "memory usage, and pod events.  Returns the current limit and a "
        "recommended new limit."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "pod_name": {"type": "string"},
            "namespace": {"type": "string"},
        },
        "required": ["pod_name", "namespace"],
    },
    output_schema={
        "type": "object",
        "properties": {
            "pod": {"type": "string"},
            "namespace": {"type": "string"},
            "current_limit": {"type": "string"},
            "current_limit_mb": {"type": "number"},
            "current_usage_mb": {"type": "number"},
            "recommended_limit_mb": {"type": "number"},
            "recommended_limit": {"type": "string"},
            "diagnosis": {"type": "string"},
        },
    },
)
async def diagnose_oomkill(pod_name: str, namespace: str) -> dict:
    """Diagnose an OOMKilled pod and recommend new memory limits."""
    core = get_core_v1()

    # ── 1. Read pod spec and status ───────────────────────────────────
    try:
        pod = core.read_namespaced_pod(name=pod_name, namespace=namespace)
    except Exception as exc:
        return {
            "pod": pod_name,
            "namespace": namespace,
            "error": f"Failed to read pod: {exc}",
        }

    # ── 2. Extract current memory limit ───────────────────────────────
    current_limit_str: Optional[str] = None
    container_name = ""

    for container in pod.spec.containers:
        container_name = container_name or container.name
        limits = getattr(container.resources, "limits", None) or {}
        if isinstance(limits, dict) and "memory" in limits:
            current_limit_str = limits["memory"]
            break

    current_limit_mb = (
        _parse_memory_to_mb(current_limit_str) if current_limit_str else None
    )

    # ── 3. Check termination reason ───────────────────────────────────
    oom_confirmed = False
    for cs in pod.status.container_statuses or []:
        terminated = None
        if cs.last_state and cs.last_state.terminated:
            terminated = cs.last_state.terminated
        elif cs.state and cs.state.terminated:
            terminated = cs.state.terminated

        if terminated and terminated.reason == "OOMKilled":
            oom_confirmed = True
            break

    # ── 4. Fetch current memory usage from Prometheus ─────────────────
    current_usage_mb: Optional[float] = None
    if settings.PROMETHEUS_URL:
        current_usage_mb = await _get_current_memory_mb(pod_name)

    # ── 5. Compute recommended limit ──────────────────────────────────
    recommended_limit_mb: Optional[float] = None
    if current_limit_mb:
        # Recommend 1.5x the current limit, rounded up to nearest 64Mi
        raw = current_limit_mb * 1.5
        recommended_limit_mb = _round_up_to(raw, 64)
    elif current_usage_mb:
        # No limit set; recommend 2x current usage
        raw = current_usage_mb * 2.0
        recommended_limit_mb = _round_up_to(raw, 64)

    recommended_limit_str = (
        f"{int(recommended_limit_mb)}Mi" if recommended_limit_mb else None
    )

    # ── 6. Build diagnosis ────────────────────────────────────────────
    lines = [f"Pod {pod_name} in {namespace} was OOMKilled."]
    if oom_confirmed:
        lines.append("Termination reason confirmed: OOMKilled.")
    if current_limit_str:
        lines.append(f"Current memory limit: {current_limit_str}.")
    else:
        lines.append("No memory limit is set on this container.")
    if current_usage_mb is not None:
        lines.append(f"Last observed memory usage: {current_usage_mb:.1f} MB.")
    if recommended_limit_str:
        lines.append(
            f"Recommended new limit: {recommended_limit_str} "
            f"({recommended_limit_mb:.0f} Mi)."
        )

    return {
        "pod": pod_name,
        "namespace": namespace,
        "container": container_name,
        "oom_confirmed": oom_confirmed,
        "current_limit": current_limit_str,
        "current_limit_mb": current_limit_mb,
        "current_usage_mb": current_usage_mb,
        "recommended_limit_mb": recommended_limit_mb,
        "recommended_limit": recommended_limit_str,
        "diagnosis": " ".join(lines),
        "assessed_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Helpers ───────────────────────────────────────────────────────────────


def _parse_memory_to_mb(mem_str: str) -> float:
    """Convert a Kubernetes memory string to megabytes."""
    units = {
        "Ki": 1024 / _BYTES_PER_MB,
        "Mi": 1.0,
        "Gi": 1024.0,
        "Ti": 1024 * 1024.0,
    }
    for suffix, factor in sorted(units.items(), key=lambda x: -len(x[0])):
        if mem_str.endswith(suffix):
            return float(mem_str[: -len(suffix)]) * factor
    # Plain bytes
    return float(mem_str) / _BYTES_PER_MB


def _round_up_to(value: float, multiple: int) -> float:
    """Round *value* up to the next multiple of *multiple*."""
    import math

    return math.ceil(value / multiple) * multiple


async def _get_current_memory_mb(pod_name: str) -> Optional[float]:
    """Query Prometheus for the latest memory working-set of a pod."""
    query = f'container_memory_working_set_bytes{{pod="{pod_name}"}}'
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{settings.PROMETHEUS_URL}/api/v1/query",
                params={"query": query},
            )
            resp.raise_for_status()
            data = resp.json()

        results = data.get("data", {}).get("result", [])
        if results:
            value = float(results[0]["value"][1])
            return round(value / _BYTES_PER_MB, 2)
    except Exception as exc:
        logger.debug("Prometheus memory query failed for %s: %s", pod_name, exc)

    return None
