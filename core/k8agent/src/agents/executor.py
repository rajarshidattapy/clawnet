"""Executor Agent -- safe remediation specialist.

Carries out approved remediation actions against the cluster.
Uses Sonnet (fast model) for quick, deterministic execution.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from langchain_anthropic import ChatAnthropic
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

from core.k8agent.src.config import settings
from core.k8agent.src.mcp_server.kubectl_tools import delete_pod as _delete_pod
from core.k8agent.src.mcp_server.kubectl_tools import get_pods as _get_pods
from core.k8agent.src.mcp_server.kubectl_tools import (
    patch_deployment_resources as _patch_deployment_resources,
)
from core.k8agent.src.mcp_server.kubectl_tools import (
    rollback_deployment as _rollback_deployment,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protected namespaces that must never be targeted
# ---------------------------------------------------------------------------

PROTECTED_NAMESPACES = frozenset({
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "default",
})

# ---------------------------------------------------------------------------
# LangChain tool wrappers
# ---------------------------------------------------------------------------


@tool
async def delete_pod_tool(
    name: str,
    namespace: str = "k8swhisperer-demo",
) -> str:
    """Delete a pod to trigger a fresh restart via its controller."""
    if namespace in PROTECTED_NAMESPACES:
        return json.dumps({
            "error": f"BLOCKED: refusing to delete pod in protected namespace '{namespace}'"
        })
    try:
        result = _delete_pod(name=name, namespace=namespace)
        return json.dumps(result, default=str)
    except Exception as exc:
        logger.exception("delete_pod_tool failed")
        return json.dumps({"error": str(exc)})


@tool
async def patch_deployment_resources_tool(
    name: str,
    namespace: str,
    container_name: str = "",
    memory_limit: str = "",
    cpu_limit: str = "",
) -> str:
    """Patch resource limits on a deployment's container."""
    if namespace in PROTECTED_NAMESPACES:
        return json.dumps({
            "error": f"BLOCKED: refusing to patch deployment in protected namespace '{namespace}'"
        })
    try:
        result = _patch_deployment_resources(
            name=name,
            namespace=namespace,
            container_name=container_name,
            memory_limit=memory_limit,
            cpu_limit=cpu_limit,
        )
        return json.dumps(result, default=str)
    except Exception as exc:
        logger.exception("patch_deployment_resources_tool failed")
        return json.dumps({"error": str(exc)})


@tool
async def rollback_deployment_tool(
    name: str,
    namespace: str = "k8swhisperer-demo",
) -> str:
    """Rollback a deployment to its previous revision."""
    if namespace in PROTECTED_NAMESPACES:
        return json.dumps({
            "error": f"BLOCKED: refusing to rollback deployment in protected namespace '{namespace}'"
        })
    try:
        result = _rollback_deployment(name=name, namespace=namespace)
        return json.dumps(result, default=str)
    except Exception as exc:
        logger.exception("rollback_deployment_tool failed")
        return json.dumps({"error": str(exc)})


@tool
async def verify_pod_health_tool(
    namespace: str = "k8swhisperer-demo",
) -> str:
    """Verify pod health after a remediation action to confirm the fix worked."""
    try:
        result = _get_pods(namespace=namespace)
        return json.dumps(result, default=str)
    except Exception as exc:
        logger.exception("verify_pod_health_tool failed")
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

EXECUTOR_SYSTEM_PROMPT = """\
You are a Kubernetes Executor agent -- responsible for safely applying
approved remediation actions to the cluster.

### Safety rules (MANDATORY)
1. NEVER delete pods or modify resources in these namespaces:
   kube-system, kube-public, kube-node-lease, default.
2. NEVER perform an action that was not explicitly approved in the
   remediation plan provided to you.
3. ALWAYS verify the result of your action by checking pod health
   after execution.
4. If an action fails, report the failure clearly -- do NOT retry
   automatically. The Commander will decide next steps.

### Execution protocol
1. Parse the approved remediation plan.
2. Execute the specified action using the appropriate tool.
3. Wait briefly, then verify that the target pod/deployment has
   recovered (Running, Ready, no new crash events).
4. Report the outcome with:
   - "status": "success" or "failure"
   - "action_taken": what you did
   - "verification": post-action pod/deployment state
   - "notes": any warnings or observations

### Supported actions
- delete_pod: Delete a crashing pod to trigger controller restart
- patch_deployment_resources: Adjust memory/CPU limits
- rollback_deployment: Roll back to previous known-good revision
"""

# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

_model_name = settings.LITELLM_MODEL_FAST.removeprefix("anthropic/")

_llm = ChatAnthropic(
    model=_model_name,
    max_tokens=4096,
    anthropic_api_key=settings.LLM_API_KEY or None,
)

executor_agent = create_react_agent(
    model=_llm,
    tools=[
        delete_pod_tool,
        patch_deployment_resources_tool,
        rollback_deployment_tool,
        verify_pod_health_tool,
    ],
    prompt=EXECUTOR_SYSTEM_PROMPT,
    name="executor",
)
