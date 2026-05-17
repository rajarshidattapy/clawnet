"""Scout Agent -- cluster reconnaissance specialist.

Gathers comprehensive cluster state by inspecting pods, events, and nodes.
Uses Sonnet (fast model) for quick data gathering and summarisation.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from langchain_anthropic import ChatAnthropic
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

from core.k8agent.src.config import settings
from core.k8agent.src.mcp_server.kubectl_tools import get_events as _get_events
from core.k8agent.src.mcp_server.kubectl_tools import get_nodes as _get_nodes
from core.k8agent.src.mcp_server.kubectl_tools import get_pods as _get_pods

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LangChain tool wrappers
# ---------------------------------------------------------------------------


@tool
async def get_pods_tool(namespace: str = "k8swhisperer-demo") -> str:
    """List pods with name, phase, restart count, ready status, conditions, and container statuses."""
    try:
        result = _get_pods(namespace=namespace)
        return json.dumps(result, default=str)
    except Exception as exc:
        logger.exception("get_pods_tool failed")
        return json.dumps({"error": str(exc)})


@tool
async def get_events_tool(namespace: str = "k8swhisperer-demo", limit: int = 50) -> str:
    """List recent Kubernetes events in the namespace, sorted by last timestamp descending."""
    try:
        result = _get_events(namespace=namespace, limit=limit)
        return json.dumps(result, default=str)
    except Exception as exc:
        logger.exception("get_events_tool failed")
        return json.dumps({"error": str(exc)})


@tool
async def get_nodes_tool() -> str:
    """List cluster nodes with conditions, capacity, and allocatable resources."""
    try:
        result = _get_nodes()
        return json.dumps(result, default=str)
    except Exception as exc:
        logger.exception("get_nodes_tool failed")
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SCOUT_SYSTEM_PROMPT = """\
You are a Kubernetes Scout agent. Your mission is to gather comprehensive
cluster state information to support incident investigation.

### Responsibilities
1. List all pods in the target namespace -- note any that are not Running/Ready.
2. Collect recent events, especially Warnings (BackOff, Failed, Unhealthy, etc.).
3. Check node health -- look for NotReady, MemoryPressure, DiskPressure conditions.

### Output format
Return structured findings as a JSON object with these keys:
- "unhealthy_pods": list of pods that are NOT Running or have restarts > 0
- "warning_events": list of Warning-type events
- "node_issues": list of nodes with problematic conditions
- "summary": a 2-3 sentence overview of cluster health

Be thorough. Collect ALL available data before forming your summary.
Do NOT speculate on root causes -- that is the Doctor agent's job.
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

scout_agent = create_react_agent(
    model=_llm,
    tools=[get_pods_tool, get_events_tool, get_nodes_tool],
    prompt=SCOUT_SYSTEM_PROMPT,
    name="scout",
)
