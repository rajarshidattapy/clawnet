"""Analyse memory trends across pods and detect accelerating restart patterns.

Works in tandem with :mod:`src.prediction.oom_predictor` to surface pods
that are trending toward failure before they actually crash.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from core.k8agent.src.config import settings
from core.k8agent.src.prediction.oom_predictor import predict_oom
from core.k8agent.src.utils.k8s_client import get_core_v1

logger = logging.getLogger(__name__)


async def analyze_pod_trends(namespace: str) -> list[dict]:
    """Check every running pod in *namespace* for OOM risk.

    Returns a list of prediction dicts (from :func:`predict_oom`) for pods
    whose memory growth puts them at risk of being OOM-killed within the
    alerting horizon.
    """
    if not settings.ENABLE_PREDICTIVE_ALERTING:
        logger.info("Predictive alerting disabled; skipping trend analysis")
        return []

    try:
        core = get_core_v1()
        pod_list = core.list_namespaced_pod(namespace=namespace)
    except Exception as exc:
        logger.error("Failed to list pods in namespace %s: %s", namespace, exc)
        return []

    at_risk: list[dict] = []

    for pod in pod_list.items:
        pod_name = pod.metadata.name
        phase = (pod.status.phase or "").lower()
        if phase not in ("running", "pending"):
            continue

        prediction = await predict_oom(pod_name, namespace)
        if prediction is not None:
            logger.warning(
                "Pod %s/%s predicted OOM in %.0fs (confidence %.2f)",
                namespace,
                pod_name,
                prediction["predicted_oom_in_seconds"],
                prediction["confidence"],
            )
            at_risk.append(prediction)

    return at_risk


async def check_restart_frequency(
    pod_name: str,
    namespace: str,
) -> Optional[dict]:
    """Detect whether a pod's restart frequency is accelerating.

    Compares restart intervals to determine if the gap between restarts is
    shrinking (i.e. the problem is getting worse, not recovering).

    Returns a dict with restart analysis or ``None`` if there are fewer
    than three restarts or the pattern is stable / improving.
    """
    try:
        core = get_core_v1()
        pod = core.read_namespaced_pod(name=pod_name, namespace=namespace)
    except Exception as exc:
        logger.error("Failed to read pod %s/%s: %s", namespace, pod_name, exc)
        return None

    # Collect restart timestamps from container statuses
    restart_times: list[datetime] = []
    total_restarts = 0

    for cs in pod.status.container_statuses or []:
        total_restarts += cs.restart_count or 0

        # last_state gives us the most recent previous run
        if cs.last_state and cs.last_state.terminated:
            finished = cs.last_state.terminated.finished_at
            if finished:
                restart_times.append(finished)

    # Also check events for more granular restart history
    try:
        events = core.list_namespaced_event(
            namespace=namespace,
            field_selector=f"involvedObject.name={pod_name},reason=BackOff",
        )
        for event in events.items:
            if event.last_timestamp:
                restart_times.append(event.last_timestamp)
            elif event.event_time:
                restart_times.append(event.event_time)
    except Exception as exc:
        logger.debug("Could not fetch events for %s: %s", pod_name, exc)

    if len(restart_times) < 3:
        return None

    restart_times.sort()

    # Calculate intervals between consecutive restarts
    intervals: list[float] = []
    for i in range(1, len(restart_times)):
        delta = (restart_times[i] - restart_times[i - 1]).total_seconds()
        if delta > 0:
            intervals.append(delta)

    if len(intervals) < 2:
        return None

    # Check if intervals are shrinking (accelerating)
    recent_avg = sum(intervals[-2:]) / 2
    earlier_avg = sum(intervals[:-2]) / max(len(intervals) - 2, 1) if len(intervals) > 2 else intervals[0]

    is_accelerating = recent_avg < earlier_avg * 0.8  # 20% shorter intervals

    if not is_accelerating:
        return None

    acceleration_factor = earlier_avg / recent_avg if recent_avg > 0 else float("inf")

    return {
        "pod": pod_name,
        "namespace": namespace,
        "total_restarts": total_restarts,
        "restart_count_observed": len(restart_times),
        "avg_interval_seconds": round(sum(intervals) / len(intervals), 1),
        "recent_interval_seconds": round(recent_avg, 1),
        "earlier_interval_seconds": round(earlier_avg, 1),
        "acceleration_factor": round(acceleration_factor, 2),
        "is_accelerating": True,
        "assessed_at": datetime.now(timezone.utc).isoformat(),
    }
