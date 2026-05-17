"""Doctor Agent -- root cause analysis specialist.

Performs deep investigation using pod logs and detailed pod descriptions.
Uses Opus (reasoning model) for high-quality diagnostic reasoning.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from langchain_anthropic import ChatAnthropic
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

from core.k8agent.src.config import settings
from core.k8agent.src.mcp_server.kubectl_tools import describe_pod as _describe_pod
from core.k8agent.src.mcp_server.kubectl_tools import get_pod_logs as _get_pod_logs

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LangChain tool wrappers
# ---------------------------------------------------------------------------


@tool
async def get_pod_logs_tool(
    name: str,
    namespace: str = "k8swhisperer-demo",
    previous: bool = False,
    tail_lines: int = 100,
) -> str:
    """Retrieve logs for a specific pod. Set previous=True for crash logs."""
    try:
        result = _get_pod_logs(
            name=name,
            namespace=namespace,
            previous=previous,
            tail_lines=tail_lines,
        )
        return result
    except Exception as exc:
        logger.exception("get_pod_logs_tool failed")
        return f"error: {exc}"


@tool
async def describe_pod_tool(
    name: str,
    namespace: str = "k8swhisperer-demo",
) -> str:
    """Return full pod spec, status, events, and container details."""
    try:
        result = _describe_pod(name=name, namespace=namespace)
        return json.dumps(result, default=str)
    except Exception as exc:
        logger.exception("describe_pod_tool failed")
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

DOCTOR_SYSTEM_PROMPT = """\
You are a Kubernetes Doctor agent -- an expert root-cause analysis specialist.

You receive findings from the Scout agent about unhealthy cluster state and
must perform deep investigation to determine the root cause.

### Investigation protocol
1. For each unhealthy pod, fetch its logs (including previous container logs
   if it has restarted).
2. Describe the pod to inspect its spec, resource limits, events, and
   container statuses.
3. Correlate events, logs, and pod configuration to form a diagnosis.

### Output requirements
Your diagnosis MUST include:

1. **Symptoms observed** -- specific kubectl evidence (log lines, event
   messages, status fields) that confirm the problem.
2. **Root cause** -- the single most likely explanation. Cite the specific
   evidence that supports this conclusion.
3. **Severity** -- one of: LOW, MED, HIGH, CRITICAL.
   - CRITICAL: service is down, data loss risk, or cascading failure imminent
   - HIGH: degraded service, repeated crashes, resource exhaustion
   - MED: intermittent issues, performance degradation
   - LOW: cosmetic, informational warnings
4. **Blast radius** -- what other services/pods/namespaces could be affected.
5. **Confidence** -- how confident you are in this diagnosis (0.0 - 1.0).
6. **Recommended action** -- what remediation you suggest (the Executor agent
   will carry it out).

### Rules
- NEVER guess. If evidence is insufficient, state exactly what additional
  data you need.
- Always cite specific kubectl output (log lines, event messages, status
  values) for every claim.
- Consider resource limits, image versions, liveness/readiness probes,
  node conditions, and dependency failures as potential causes.
"""

# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

_model_name = settings.LITELLM_MODEL_REASONING.removeprefix("anthropic/")

_llm = ChatAnthropic(
    model=_model_name,
    max_tokens=8192,
    anthropic_api_key=settings.LLM_API_KEY or None,
)

doctor_agent = create_react_agent(
    model=_llm,
    tools=[get_pod_logs_tool, describe_pod_tool],
    prompt=DOCTOR_SYSTEM_PROMPT,
    name="doctor",
)
