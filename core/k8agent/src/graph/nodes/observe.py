"""Observe node — collects raw cluster state for anomaly detection."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from core.k8agent.src.config import settings
from core.k8agent.src.graph.state import ClusterState
from core.k8agent.src.utils.k8s_client import get_apps_v1, get_autoscaling_v1, get_core_v1

logger = logging.getLogger(__name__)

_SKIP_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease", "local-path-storage"})


def _iso(dt) -> str | None:
    """Safely convert a k8s datetime to ISO string."""
    if dt is None:
        return None
    if isinstance(dt, datetime):
        return dt.isoformat()
    return str(dt)


def observe_node(state: ClusterState) -> dict:
    """Collect pod statuses, recent events, and deployment rollout info.

    Returns ``{"events": [...]}`` where each entry is a normalised dict
    suitable for the classifier LLM.
    """
    # Skip observation if events are already pre-populated (multi-anomaly processing)
    if state.get("events"):
        logger.info("observe_node: skipping — events already populated (%d)", len(state["events"]))
        # Return empty — state already has them, operator.add would double them
        return {"events": []}

    primary_namespace = settings.NAMESPACE
    if primary_namespace in _SKIP_NAMESPACES:
        logger.warning("Configured NAMESPACE '%s' is in skip list; observing anyway.", primary_namespace)

    normalised: list[dict] = []

    try:
        core = get_core_v1()

        # ── Determine namespaces to scan ─────────────────────────────
        if settings.ENABLE_MULTI_NAMESPACE:
            all_ns = core.list_namespace()
            namespaces = [
                ns.metadata.name
                for ns in all_ns.items
                if ns.metadata.name not in _SKIP_NAMESPACES
            ]
            logger.info("Multi-namespace mode: scanning %d namespaces", len(namespaces))
        else:
            namespaces = [primary_namespace]

        for namespace in namespaces:
            # ── Pods ─────────────────────────────────────────────────────
            pods = core.list_namespaced_pod(namespace=namespace)
            for pod in pods.items:
                if (pod.metadata.namespace or "") in _SKIP_NAMESPACES:
                    continue

                container_statuses = []
                for cs in pod.status.container_statuses or []:
                    state_str = "unknown"
                    reason = None
                    if cs.state.running:
                        state_str = "running"
                    elif cs.state.waiting:
                        state_str = "waiting"
                        reason = cs.state.waiting.reason
                    elif cs.state.terminated:
                        state_str = "terminated"
                        reason = cs.state.terminated.reason

                    container_statuses.append({
                        "name": cs.name,
                        "ready": cs.ready,
                        "restart_count": cs.restart_count,
                        "state": state_str,
                        "reason": reason,
                        "image": cs.image,
                    })

                normalised.append({
                    "kind": "Pod",
                    "name": pod.metadata.name,
                    "namespace": pod.metadata.namespace,
                    "phase": pod.status.phase,
                    "container_statuses": container_statuses,
                    "conditions": [
                        {
                            "type": c.type,
                            "status": c.status,
                            "reason": c.reason,
                            "message": c.message,
                        }
                        for c in (pod.status.conditions or [])
                    ],
                    "node_name": pod.spec.node_name,
                    "timestamp": _iso(pod.metadata.creation_timestamp),
                })

            # ── Events (last 5 minutes) ─────────────────────────────────
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
            events = core.list_namespaced_event(namespace=namespace)
            for ev in events.items:
                last_ts = ev.last_timestamp or ev.event_time
                if last_ts and last_ts.replace(tzinfo=timezone.utc) < cutoff:
                    continue

                normalised.append({
                    "kind": "Event",
                    "name": ev.involved_object.name if ev.involved_object else None,
                    "namespace": ev.metadata.namespace,
                    "reason": ev.reason,
                    "message": ev.message,
                    "type": ev.type,
                    "count": ev.count,
                    "first_seen": _iso(ev.first_timestamp),
                    "last_seen": _iso(last_ts),
                    "involved_kind": ev.involved_object.kind if ev.involved_object else None,
                })

            # ── Deployment rollout status ────────────────────────────────
            try:
                apps = get_apps_v1()
                deployments = apps.list_namespaced_deployment(namespace=namespace)
                for dep in deployments.items:
                    desired = dep.spec.replicas or 0
                    updated = dep.status.updated_replicas or 0
                    available = dep.status.available_replicas or 0
                    if updated < desired or available < desired:
                        normalised.append({
                            "kind": "DeploymentRollout",
                            "name": dep.metadata.name,
                            "namespace": dep.metadata.namespace,
                            "desired_replicas": desired,
                            "updated_replicas": updated,
                            "available_replicas": available,
                            "conditions": [
                                {
                                    "type": c.type,
                                    "status": c.status,
                                    "reason": c.reason,
                                    "message": c.message,
                                }
                                for c in (dep.status.conditions or [])
                            ],
                            "timestamp": _iso(dep.metadata.creation_timestamp),
                        })
            except Exception:
                logger.exception("Failed to check deployment rollout status in namespace %s", namespace)

            # ── HPA status ──────────────────────────────────────────────────
            try:
                autoscaling = get_autoscaling_v1()
                hpa_list = autoscaling.list_namespaced_horizontal_pod_autoscaler(
                    namespace=namespace,
                )
                for hpa in hpa_list.items:
                    current_replicas = hpa.status.current_replicas or 0
                    desired_replicas = hpa.status.desired_replicas or 0
                    current_cpu = hpa.status.current_cpu_utilization_percentage
                    target_cpu = hpa.spec.target_cpu_utilization_percentage

                    hpa_event = {
                        "kind": "HPA",
                        "name": hpa.metadata.name,
                        "namespace": hpa.metadata.namespace,
                        "min_replicas": hpa.spec.min_replicas,
                        "max_replicas": hpa.spec.max_replicas,
                        "current_replicas": current_replicas,
                        "desired_replicas": desired_replicas,
                        "current_cpu_utilization_percentage": current_cpu,
                        "target_cpu_utilization_percentage": target_cpu,
                        "scaling_active": current_replicas != desired_replicas,
                        "target_ref": hpa.spec.scale_target_ref.name if hpa.spec.scale_target_ref else None,
                        "timestamp": _iso(hpa.metadata.creation_timestamp),
                    }
                    normalised.append(hpa_event)

                    # Emit an additional scaling event when HPA is actively scaling
                    if current_replicas != desired_replicas:
                        normalised.append({
                            "kind": "Event",
                            "name": hpa.metadata.name,
                            "namespace": hpa.metadata.namespace,
                            "reason": "HPAScaling",
                            "message": (
                                f"HPA '{hpa.metadata.name}' is scaling "
                                f"'{hpa.spec.scale_target_ref.name}' from "
                                f"{current_replicas} to {desired_replicas} replicas "
                                f"(CPU utilization: {current_cpu}%, target: {target_cpu}%)"
                            ),
                            "type": "Normal",
                            "count": 1,
                            "first_seen": _iso(hpa.metadata.creation_timestamp),
                            "last_seen": _iso(datetime.now(timezone.utc)),
                            "involved_kind": "HorizontalPodAutoscaler",
                        })
            except Exception:
                logger.exception("Failed to check HPA status in namespace %s", namespace)

    except Exception:
        logger.exception("observe_node failed to collect cluster state")

    logger.info("observe_node collected %d events/signals", len(normalised))
    return {"events": normalised}
