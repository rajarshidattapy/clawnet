"""FastMCP server exposing typed kubectl tools via the kubernetes Python client.

All operations use the Python kubernetes client — no subprocess / kubectl binary.
"""

from __future__ import annotations

import logging
from typing import Any

from kubernetes.client import V1DeleteOptions
from mcp.server.fastmcp import FastMCP

from core.k8agent.src.utils.k8s_client import get_apps_v1, get_autoscaling_v1, get_core_v1

logger = logging.getLogger(__name__)

mcp_server = FastMCP(name="kubectl-tools")

# ── Helpers ──────────────────────────────────────────────────────────────


def _error(msg: str, exc: Exception | None = None) -> dict[str, Any]:
    """Return a standardised error dict."""
    d: dict[str, Any] = {"error": msg}
    if exc:
        d["detail"] = str(exc)
    return d


def _container_statuses(pod) -> list[dict]:
    """Extract container statuses from a pod object."""
    statuses: list[dict] = []
    for cs in pod.status.container_statuses or []:
        statuses.append(
            {
                "name": cs.name,
                "ready": cs.ready,
                "restart_count": cs.restart_count,
                "state": (
                    "running"
                    if cs.state.running
                    else "waiting"
                    if cs.state.waiting
                    else "terminated"
                    if cs.state.terminated
                    else "unknown"
                ),
                "reason": (
                    (cs.state.waiting.reason if cs.state.waiting else None)
                    or (cs.state.terminated.reason if cs.state.terminated else None)
                ),
            }
        )
    return statuses


# ── Pod tools ────────────────────────────────────────────────────────────


@mcp_server.tool()
def get_pods(namespace: str = "k8swhisperer-demo") -> list[dict]:
    """List pods with name, phase, restartCount, ready status, conditions, and containerStatuses."""
    try:
        core = get_core_v1()
        pod_list = core.list_namespaced_pod(namespace=namespace)
        results: list[dict] = []
        for pod in pod_list.items:
            conditions = []
            for c in pod.status.conditions or []:
                conditions.append(
                    {
                        "type": c.type,
                        "status": c.status,
                        "reason": c.reason,
                        "message": c.message,
                    }
                )

            total_restarts = sum(
                cs.restart_count for cs in (pod.status.container_statuses or [])
            )
            all_ready = all(
                cs.ready for cs in (pod.status.container_statuses or [])
            )

            results.append(
                {
                    "name": pod.metadata.name,
                    "namespace": pod.metadata.namespace,
                    "phase": pod.status.phase,
                    "restart_count": total_restarts,
                    "ready": all_ready,
                    "conditions": conditions,
                    "container_statuses": _container_statuses(pod),
                }
            )
        return results
    except Exception as exc:
        logger.exception("get_pods failed")
        return [_error("Failed to list pods", exc)]


@mcp_server.tool()
def get_pod_logs(
    name: str,
    namespace: str = "k8swhisperer-demo",
    previous: bool = False,
    tail_lines: int = 100,
) -> str:
    """Retrieve logs for a specific pod."""
    try:
        core = get_core_v1()
        return core.read_namespaced_pod_log(
            name=name,
            namespace=namespace,
            previous=previous,
            tail_lines=tail_lines,
        )
    except Exception as exc:
        logger.exception("get_pod_logs failed for %s/%s", namespace, name)
        return f"error: {exc}"


@mcp_server.tool()
def describe_pod(name: str, namespace: str = "k8swhisperer-demo") -> dict:
    """Return full pod spec, status, and related events."""
    try:
        core = get_core_v1()
        pod = core.read_namespaced_pod(name=name, namespace=namespace)

        # Fetch events for this pod
        field = f"involvedObject.name={name}"
        events = core.list_namespaced_event(namespace=namespace, field_selector=field)
        event_list = [
            {
                "reason": e.reason,
                "message": e.message,
                "count": e.count,
                "first_seen": e.first_timestamp.isoformat() if e.first_timestamp else None,
                "last_seen": e.last_timestamp.isoformat() if e.last_timestamp else None,
                "type": e.type,
            }
            for e in events.items
        ]

        containers_spec = []
        for c in pod.spec.containers or []:
            containers_spec.append(
                {
                    "name": c.name,
                    "image": c.image,
                    "resources": {
                        "requests": dict(c.resources.requests) if c.resources and c.resources.requests else {},
                        "limits": dict(c.resources.limits) if c.resources and c.resources.limits else {},
                    },
                    "ports": [
                        {"container_port": p.container_port, "protocol": p.protocol}
                        for p in (c.ports or [])
                    ],
                }
            )

        return {
            "name": pod.metadata.name,
            "namespace": pod.metadata.namespace,
            "labels": dict(pod.metadata.labels or {}),
            "annotations": dict(pod.metadata.annotations or {}),
            "phase": pod.status.phase,
            "node_name": pod.spec.node_name,
            "service_account": pod.spec.service_account_name,
            "containers": containers_spec,
            "container_statuses": _container_statuses(pod),
            "conditions": [
                {
                    "type": c.type,
                    "status": c.status,
                    "reason": c.reason,
                    "message": c.message,
                }
                for c in (pod.status.conditions or [])
            ],
            "events": event_list,
        }
    except Exception as exc:
        logger.exception("describe_pod failed for %s/%s", namespace, name)
        return _error("Failed to describe pod", exc)


# ── Events ───────────────────────────────────────────────────────────────


@mcp_server.tool()
def get_events(namespace: str = "k8swhisperer-demo", limit: int = 50) -> list[dict]:
    """List recent events in the namespace, sorted by last timestamp descending."""
    try:
        core = get_core_v1()
        event_list = core.list_namespaced_event(namespace=namespace, limit=limit)
        events = []
        for e in event_list.items:
            events.append(
                {
                    "reason": e.reason,
                    "message": e.message,
                    "involved_object": e.involved_object.name if e.involved_object else None,
                    "kind": e.involved_object.kind if e.involved_object else None,
                    "count": e.count,
                    "type": e.type,
                    "first_seen": e.first_timestamp.isoformat() if e.first_timestamp else None,
                    "last_seen": e.last_timestamp.isoformat() if e.last_timestamp else None,
                }
            )
        # Sort by last_seen descending (None last)
        events.sort(key=lambda x: x.get("last_seen") or "", reverse=True)
        return events[:limit]
    except Exception as exc:
        logger.exception("get_events failed")
        return [_error("Failed to list events", exc)]


# ── Nodes ────────────────────────────────────────────────────────────────


@mcp_server.tool()
def get_nodes() -> list[dict]:
    """List cluster nodes with conditions, capacity, and allocatable resources."""
    try:
        core = get_core_v1()
        node_list = core.list_node()
        results: list[dict] = []
        for node in node_list.items:
            conditions = [
                {
                    "type": c.type,
                    "status": c.status,
                    "reason": c.reason,
                    "message": c.message,
                }
                for c in (node.status.conditions or [])
            ]
            results.append(
                {
                    "name": node.metadata.name,
                    "conditions": conditions,
                    "capacity": dict(node.status.capacity or {}),
                    "allocatable": dict(node.status.allocatable or {}),
                }
            )
        return results
    except Exception as exc:
        logger.exception("get_nodes failed")
        return [_error("Failed to list nodes", exc)]


# ── Mutation tools ───────────────────────────────────────────────────────


@mcp_server.tool()
def delete_pod(name: str, namespace: str = "k8swhisperer-demo") -> dict:
    """Delete a pod and return confirmation."""
    try:
        core = get_core_v1()
        core.delete_namespaced_pod(
            name=name,
            namespace=namespace,
            body=V1DeleteOptions(grace_period_seconds=30),
        )
        return {"status": "deleted", "pod": name, "namespace": namespace}
    except Exception as exc:
        # 404 = pod already gone, treat as success
        if hasattr(exc, 'status') and exc.status == 404:
            logger.info("delete_pod: pod %s/%s already gone (404)", namespace, name)
            return {"status": "deleted", "pod": name, "namespace": namespace, "note": "pod was already gone"}
        logger.exception("delete_pod failed for %s/%s", namespace, name)
        return _error("Failed to delete pod", exc)


@mcp_server.tool()
def patch_deployment_resources(
    name: str,
    namespace: str,
    container_name: str = "",
    memory_limit: str = "",
    cpu_limit: str = "",
) -> dict:
    """Patch resource limits on a deployment's container.

    If *container_name* is empty, patches the first container.
    """
    try:
        apps = get_apps_v1()
        deployment = apps.read_namespaced_deployment(name=name, namespace=namespace)

        target_idx = 0
        if container_name:
            for idx, c in enumerate(deployment.spec.template.spec.containers):
                if c.name == container_name:
                    target_idx = idx
                    break
            else:
                return _error(f"Container '{container_name}' not found in deployment '{name}'")

        patch_body: dict = {
            "spec": {
                "template": {
                    "spec": {
                        "containers": []
                    }
                }
            }
        }

        # Build the strategic-merge-patch container entry
        container_patch: dict = {"name": deployment.spec.template.spec.containers[target_idx].name}
        resources: dict = {}
        limits: dict = {}
        if memory_limit:
            limits["memory"] = memory_limit
        if cpu_limit:
            limits["cpu"] = cpu_limit
        if limits:
            resources["limits"] = limits
        if resources:
            container_patch["resources"] = resources

        # Strategic merge patch requires the full containers list with name keys
        patch_body["spec"]["template"]["spec"]["containers"] = [container_patch]

        apps.patch_namespaced_deployment(name=name, namespace=namespace, body=patch_body)
        return {
            "status": "patched",
            "deployment": name,
            "namespace": namespace,
            "container": container_patch["name"],
            "new_limits": limits,
        }
    except Exception as exc:
        logger.exception("patch_deployment_resources failed for %s/%s", namespace, name)
        return _error("Failed to patch deployment resources", exc)


@mcp_server.tool()
def rollback_deployment(name: str, namespace: str = "k8swhisperer-demo") -> dict:
    """Rollback a deployment to its previous revision.

    Sets the deprecated rollbackTo annotation then patches, which triggers
    the equivalent of ``kubectl rollout undo``.
    """
    try:
        apps = get_apps_v1()

        # List replica sets to find the previous revision
        rs_list = apps.list_namespaced_replica_set(
            namespace=namespace,
            label_selector=",".join(
                f"{k}={v}"
                for k, v in (
                    apps.read_namespaced_deployment(name=name, namespace=namespace)
                    .spec.selector.match_labels
                    or {}
                ).items()
            ),
        )

        # Sort by revision annotation descending
        def _revision(rs):
            return int(
                (rs.metadata.annotations or {}).get(
                    "deployment.kubernetes.io/revision", "0"
                )
            )

        sorted_rs = sorted(rs_list.items, key=_revision, reverse=True)
        if len(sorted_rs) < 2:
            return {
                "status": "no_op",
                "deployment": name,
                "namespace": namespace,
                "message": (
                    "No previous revision found to rollback to — this deployment "
                    "has only one revision. Manual intervention required (e.g. fix "
                    "the image tag or configuration and re-deploy)."
                ),
            }

        previous_rs = sorted_rs[1]
        prev_template = previous_rs.spec.template

        # Patch the deployment with the previous pod template
        patch_body = {
            "spec": {
                "template": {
                    "metadata": {
                        "labels": dict(prev_template.metadata.labels or {}),
                        "annotations": dict(prev_template.metadata.annotations or {}),
                    },
                    "spec": prev_template.spec.to_dict(),
                }
            }
        }

        apps.patch_namespaced_deployment(name=name, namespace=namespace, body=patch_body)
        return {
            "status": "rolled_back",
            "deployment": name,
            "namespace": namespace,
            "rolled_back_to_revision": _revision(previous_rs),
        }
    except Exception as exc:
        logger.exception("rollback_deployment failed for %s/%s", namespace, name)
        return _error("Failed to rollback deployment", exc)


# ── Deployments ──────────────────────────────────────────────────────────


@mcp_server.tool()
def get_hpa(namespace: str = "k8swhisperer-demo") -> list[dict]:
    """List Horizontal Pod Autoscalers with current/desired/max replicas and CPU utilization."""
    try:
        autoscaling = get_autoscaling_v1()
        hpa_list = autoscaling.list_namespaced_horizontal_pod_autoscaler(namespace=namespace)
        results: list[dict] = []
        for hpa in hpa_list.items:
            results.append(
                {
                    "name": hpa.metadata.name,
                    "namespace": hpa.metadata.namespace,
                    "target": hpa.spec.scale_target_ref.name if hpa.spec.scale_target_ref else None,
                    "min_replicas": hpa.spec.min_replicas,
                    "max_replicas": hpa.spec.max_replicas,
                    "current_replicas": hpa.status.current_replicas or 0,
                    "desired_replicas": hpa.status.desired_replicas or 0,
                    "current_cpu_utilization_percentage": hpa.status.current_cpu_utilization_percentage,
                    "target_cpu_utilization_percentage": hpa.spec.target_cpu_utilization_percentage,
                    "scaling_active": (hpa.status.current_replicas or 0) != (hpa.status.desired_replicas or 0),
                }
            )
        return results
    except Exception as exc:
        logger.exception("get_hpa failed")
        return [_error("Failed to list HPAs", exc)]


@mcp_server.tool()
def scale_deployment(
    name: str,
    namespace: str = "k8swhisperer-demo",
    replicas: int = 1,
) -> dict:
    """Manually scale a deployment to the specified number of replicas."""
    try:
        apps = get_apps_v1()
        patch_body = {"spec": {"replicas": replicas}}
        apps.patch_namespaced_deployment_scale(
            name=name, namespace=namespace, body=patch_body,
        )
        return {
            "status": "scaled",
            "deployment": name,
            "namespace": namespace,
            "replicas": replicas,
        }
    except Exception as exc:
        logger.exception("scale_deployment failed for %s/%s", namespace, name)
        return _error("Failed to scale deployment", exc)


@mcp_server.tool()
def get_deployments(namespace: str = "k8swhisperer-demo") -> list[dict]:
    """List deployments with replica counts and conditions."""
    try:
        apps = get_apps_v1()
        dep_list = apps.list_namespaced_deployment(namespace=namespace)
        results: list[dict] = []
        for dep in dep_list.items:
            conditions = [
                {
                    "type": c.type,
                    "status": c.status,
                    "reason": c.reason,
                    "message": c.message,
                }
                for c in (dep.status.conditions or [])
            ]
            results.append(
                {
                    "name": dep.metadata.name,
                    "namespace": dep.metadata.namespace,
                    "replicas": dep.spec.replicas,
                    "ready_replicas": dep.status.ready_replicas or 0,
                    "updated_replicas": dep.status.updated_replicas or 0,
                    "available_replicas": dep.status.available_replicas or 0,
                    "conditions": conditions,
                }
            )
        return results
    except Exception as exc:
        logger.exception("get_deployments failed")
        return [_error("Failed to list deployments", exc)]
