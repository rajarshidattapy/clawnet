"""Skill: safely delete a pod with namespace guardrails.

Refuses to delete pods in protected namespaces (kube-system, kube-public)
and waits briefly for a replacement pod to appear before returning.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from core.k8agent.src.skills.registry import skills_registry
from core.k8agent.src.utils.k8s_client import get_core_v1

logger = logging.getLogger(__name__)

# ── Protected namespaces ──────────────────────────────────────────────────

_PROTECTED_NAMESPACES: frozenset[str] = frozenset({
    "kube-system",
    "kube-public",
    "kube-node-lease",
})

_RECREATION_POLL_INTERVAL = 2  # seconds
_RECREATION_TIMEOUT = 30  # seconds


@skills_registry.skill(
    name="safe_delete_pod",
    description=(
        "Safely delete a pod after validating the namespace is not a "
        "protected system namespace.  Waits for the controller to "
        "recreate a replacement."
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
            "status": {"type": "string"},
            "replacement_pod": {"type": "string"},
        },
    },
)
async def safe_delete_pod(pod_name: str, namespace: str) -> dict:
    """Delete a pod safely with namespace protection.

    Validates that the namespace is not a protected system namespace,
    deletes the pod, and polls briefly for a replacement to appear.
    """
    # ── 1. Namespace guard ────────────────────────────────────────────
    if namespace in _PROTECTED_NAMESPACES:
        logger.warning(
            "Refused to delete pod %s in protected namespace %s",
            pod_name,
            namespace,
        )
        return {
            "pod": pod_name,
            "namespace": namespace,
            "status": "refused",
            "reason": (
                f"Namespace '{namespace}' is a protected system namespace. "
                f"Deleting pods there could destabilise the cluster."
            ),
        }

    core = get_core_v1()

    # ── 2. Verify the pod exists and capture owner info ───────────────
    try:
        pod = core.read_namespaced_pod(name=pod_name, namespace=namespace)
    except Exception as exc:
        return {
            "pod": pod_name,
            "namespace": namespace,
            "status": "error",
            "error": f"Pod not found: {exc}",
        }

    owner_refs = pod.metadata.owner_references or []
    has_controller = any(ref.controller for ref in owner_refs)

    # Record labels for matching replacement pods
    labels = pod.metadata.labels or {}

    # ── 3. Delete the pod ─────────────────────────────────────────────
    try:
        core.delete_namespaced_pod(name=pod_name, namespace=namespace)
    except Exception as exc:
        logger.error("Failed to delete pod %s/%s: %s", namespace, pod_name, exc)
        return {
            "pod": pod_name,
            "namespace": namespace,
            "status": "error",
            "error": f"Delete failed: {exc}",
        }

    logger.info("Deleted pod %s/%s", namespace, pod_name)

    # ── 4. Wait for replacement (if managed by a controller) ──────────
    replacement_pod: str | None = None
    if has_controller and labels:
        replacement_pod = await _wait_for_replacement(
            namespace=namespace,
            labels=labels,
            deleted_name=pod_name,
        )

    status = "deleted"
    if replacement_pod:
        status = "deleted_and_replaced"

    return {
        "pod": pod_name,
        "namespace": namespace,
        "status": status,
        "replacement_pod": replacement_pod,
        "had_controller": has_controller,
        "deleted_at": datetime.now(timezone.utc).isoformat(),
    }


async def _wait_for_replacement(
    namespace: str,
    labels: dict[str, str],
    deleted_name: str,
) -> str | None:
    """Poll for a new pod matching *labels* that is not *deleted_name*."""
    core = get_core_v1()
    label_selector = ",".join(f"{k}={v}" for k, v in labels.items())

    elapsed = 0.0
    while elapsed < _RECREATION_TIMEOUT:
        await asyncio.sleep(_RECREATION_POLL_INTERVAL)
        elapsed += _RECREATION_POLL_INTERVAL

        try:
            pods = core.list_namespaced_pod(
                namespace=namespace,
                label_selector=label_selector,
            )
        except Exception:
            continue

        for p in pods.items:
            if p.metadata.name != deleted_name:
                phase = (p.status.phase or "").lower()
                if phase in ("running", "pending", "containercreating"):
                    logger.info(
                        "Replacement pod %s detected (phase=%s)",
                        p.metadata.name,
                        phase,
                    )
                    return p.metadata.name

    logger.warning(
        "No replacement pod detected within %ds for %s/%s",
        _RECREATION_TIMEOUT,
        namespace,
        deleted_name,
    )
    return None
