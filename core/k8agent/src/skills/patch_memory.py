"""Skill: patch a deployment's memory limit.

Applies a strategic-merge patch to a Deployment's first container to set
the requested memory limit.  The Deployment controller will perform a
rolling update automatically.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from core.k8agent.src.skills.registry import skills_registry
from core.k8agent.src.utils.k8s_client import get_apps_v1

logger = logging.getLogger(__name__)


@skills_registry.skill(
    name="patch_memory",
    description=(
        "Patch a Deployment's memory limit for its first container.  "
        "Triggers a rolling update."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "deployment_name": {"type": "string"},
            "namespace": {"type": "string"},
            "new_memory_limit": {
                "type": "string",
                "description": "Kubernetes memory string, e.g. '512Mi', '1Gi'",
            },
        },
        "required": ["deployment_name", "namespace", "new_memory_limit"],
    },
    output_schema={
        "type": "object",
        "properties": {
            "deployment": {"type": "string"},
            "namespace": {"type": "string"},
            "new_memory_limit": {"type": "string"},
            "status": {"type": "string"},
        },
    },
)
async def patch_memory(
    deployment_name: str,
    namespace: str,
    new_memory_limit: str,
) -> dict:
    """Patch the memory limit of a Deployment's first container.

    Returns a result dict indicating success or failure.
    """
    apps = get_apps_v1()

    # ── 1. Verify the deployment exists ───────────────────────────────
    try:
        deployment = apps.read_namespaced_deployment(
            name=deployment_name,
            namespace=namespace,
        )
    except Exception as exc:
        return {
            "deployment": deployment_name,
            "namespace": namespace,
            "new_memory_limit": new_memory_limit,
            "status": "error",
            "error": f"Deployment not found: {exc}",
        }

    # Capture the previous limit for the response
    containers = deployment.spec.template.spec.containers
    previous_limit = None
    if containers:
        limits = getattr(containers[0].resources, "limits", None) or {}
        if isinstance(limits, dict):
            previous_limit = limits.get("memory")

    # ── 2. Build and apply the patch ──────────────────────────────────
    patch_body = {
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": containers[0].name if containers else "main",
                            "resources": {
                                "limits": {
                                    "memory": new_memory_limit,
                                },
                            },
                        }
                    ]
                }
            }
        }
    }

    try:
        apps.patch_namespaced_deployment(
            name=deployment_name,
            namespace=namespace,
            body=patch_body,
        )
    except Exception as exc:
        logger.error(
            "Failed to patch deployment %s/%s: %s",
            namespace,
            deployment_name,
            exc,
        )
        return {
            "deployment": deployment_name,
            "namespace": namespace,
            "new_memory_limit": new_memory_limit,
            "status": "error",
            "error": f"Patch failed: {exc}",
        }

    logger.info(
        "Patched deployment %s/%s memory limit: %s -> %s",
        namespace,
        deployment_name,
        previous_limit,
        new_memory_limit,
    )

    return {
        "deployment": deployment_name,
        "namespace": namespace,
        "previous_limit": previous_limit,
        "new_memory_limit": new_memory_limit,
        "status": "patched",
        "patched_at": datetime.now(timezone.utc).isoformat(),
    }
