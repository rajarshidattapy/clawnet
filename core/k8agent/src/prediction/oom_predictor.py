"""Predictive OOM detection using Prometheus memory metrics and linear regression.

Queries container_memory_working_set_bytes over a 5-minute window, fits a
linear trend, and extrapolates when the pod will hit its memory limit.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx
import numpy as np

from core.k8agent.src.config import settings
from core.k8agent.src.utils.k8s_client import get_core_v1

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────

_QUERY_RANGE_PATH = "/api/v1/query_range"
_OOM_HORIZON_SECONDS = 30 * 60  # alert if OOM predicted within 30 minutes
_STEP_SECONDS = 15
_RANGE_MINUTES = 5
_BYTES_PER_MB = 1024 * 1024


async def predict_oom(
    pod_name: str,
    namespace: str,
) -> Optional[dict]:
    """Predict whether *pod_name* in *namespace* will be OOM-killed soon.

    Returns a prediction dict when OOM is estimated within 30 minutes,
    or ``None`` if memory is not growing or data is insufficient.
    """
    if not settings.PROMETHEUS_URL:
        logger.warning("PROMETHEUS_URL not configured; skipping OOM prediction")
        return None

    # ── 1. Fetch memory time-series from Prometheus ───────────────────
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=_RANGE_MINUTES)

    query = f'container_memory_working_set_bytes{{pod="{pod_name}"}}'

    params = {
        "query": query,
        "start": start.isoformat(),
        "end": end.isoformat(),
        "step": f"{_STEP_SECONDS}s",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{settings.PROMETHEUS_URL}{_QUERY_RANGE_PATH}",
                params=params,
            )
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, httpx.InvalidURL) as exc:
        logger.error("Prometheus query failed for pod %s: %s", pod_name, exc)
        return None

    # ── 2. Parse result matrix ────────────────────────────────────────
    results = data.get("data", {}).get("result", [])
    if not results:
        logger.debug("No Prometheus data for pod %s", pod_name)
        return None

    # Use the first matching time-series (primary container)
    values = results[0].get("values", [])
    if len(values) < 4:
        logger.debug("Insufficient data points (%d) for pod %s", len(values), pod_name)
        return None

    timestamps = np.array([float(v[0]) for v in values])
    mem_bytes = np.array([float(v[1]) for v in values])

    # ── 3. Linear regression ──────────────────────────────────────────
    # Normalise timestamps to seconds-from-start for numerical stability
    t_offset = timestamps - timestamps[0]
    coeffs = np.polyfit(t_offset, mem_bytes, 1)
    slope = coeffs[0]  # bytes per second

    if slope <= 0:
        logger.debug("Memory not growing for pod %s (slope=%.2f B/s)", pod_name, slope)
        return None

    current_memory = float(mem_bytes[-1])

    # ── 4. Get pod memory limit from Kubernetes ───────────────────────
    limit_bytes = await _get_memory_limit(pod_name, namespace)
    if limit_bytes is None:
        logger.debug("No memory limit set for pod %s; cannot predict OOM", pod_name)
        return None

    remaining = limit_bytes - current_memory
    if remaining <= 0:
        # Already at or above limit
        time_to_oom = 0.0
    else:
        time_to_oom = remaining / slope

    if time_to_oom > _OOM_HORIZON_SECONDS:
        logger.debug(
            "OOM for pod %s predicted in %.0fs (>%ds horizon); no alert",
            pod_name,
            time_to_oom,
            _OOM_HORIZON_SECONDS,
        )
        return None

    # ── 5. Compute confidence based on R-squared ──────────────────────
    predicted = np.polyval(coeffs, t_offset)
    ss_res = np.sum((mem_bytes - predicted) ** 2)
    ss_tot = np.sum((mem_bytes - np.mean(mem_bytes)) ** 2)
    r_squared = 1.0 - (ss_res / ss_tot) if ss_tot > 0 else 0.0
    confidence = max(0.0, min(1.0, r_squared))

    predicted_oom_at = datetime.now(timezone.utc) + timedelta(seconds=time_to_oom)

    return {
        "pod": pod_name,
        "namespace": namespace,
        "current_memory_mb": round(current_memory / _BYTES_PER_MB, 2),
        "limit_mb": round(limit_bytes / _BYTES_PER_MB, 2),
        "growth_rate_mb_per_sec": round(slope / _BYTES_PER_MB, 4),
        "predicted_oom_in_seconds": round(time_to_oom, 1),
        "predicted_oom_at": predicted_oom_at.isoformat(),
        "confidence": round(confidence, 3),
    }


async def _get_memory_limit(pod_name: str, namespace: str) -> Optional[float]:
    """Retrieve the memory limit (in bytes) for the first container in a pod."""
    try:
        core = get_core_v1()
        pod = core.read_namespaced_pod(name=pod_name, namespace=namespace)
    except Exception as exc:
        logger.error("Failed to read pod %s/%s: %s", namespace, pod_name, exc)
        return None

    for container in pod.spec.containers:
        limits = (container.resources or {}) and (
            getattr(container.resources, "limits", None) or {}
        )
        mem_str = limits.get("memory") if isinstance(limits, dict) else None
        if mem_str:
            return _parse_memory_string(mem_str)

    return None


def _parse_memory_string(mem_str: str) -> float:
    """Convert a Kubernetes memory string (e.g. '512Mi', '1Gi') to bytes."""
    units = {
        "Ki": 1024,
        "Mi": 1024**2,
        "Gi": 1024**3,
        "Ti": 1024**4,
        "K": 1000,
        "M": 1000**2,
        "G": 1000**3,
        "T": 1000**4,
    }
    for suffix, multiplier in sorted(units.items(), key=lambda x: -len(x[0])):
        if mem_str.endswith(suffix):
            return float(mem_str[: -len(suffix)]) * multiplier
    # Plain bytes
    return float(mem_str)
