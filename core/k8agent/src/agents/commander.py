"""Incident Commander -- supervisor agent that coordinates the swarm.

Orchestrates the Scout, Doctor, Executor, and Comms agents through a
structured incident response protocol using LangGraph's supervisor pattern.

Protocol:
    1. Scout gathers cluster state
    2. Doctor diagnoses root cause
    3. Safety check on proposed remediation
    4. Executor applies approved fix (with human-in-the-loop for destructive actions)
    5. Comms posts updates and post-mortem

Uses Opus (reasoning model) for best coordination and decision-making.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from langchain_anthropic import ChatAnthropic
from langgraph.checkpoint.memory import MemorySaver
from langgraph_supervisor import create_supervisor

from core.k8agent.src.agents.comms import comms_agent
from core.k8agent.src.agents.doctor import doctor_agent
from core.k8agent.src.agents.executor import executor_agent
from core.k8agent.src.agents.scout import scout_agent
from core.k8agent.src.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Supervisor system prompt
# ---------------------------------------------------------------------------

COMMANDER_SYSTEM_PROMPT = """\
You are the K8sWhisperer Incident Commander -- a senior SRE supervisor
coordinating a team of specialist agents to resolve Kubernetes incidents.

### Your team
- **scout**: Cluster reconnaissance. Gathers pod statuses, events, node health.
- **doctor**: Root cause analysis. Investigates logs and pod details to diagnose issues.
- **executor**: Remediation. Executes approved fixes (pod deletion, resource patching, rollbacks).
- **comms**: Communications. Posts incident updates and post-mortems to Slack.

### Incident response protocol (follow this order strictly)

**Phase 1 -- Reconnaissance**
Delegate to `scout` to gather comprehensive cluster state. Provide the
namespace and any known symptoms from the incident description.

**Phase 2 -- Diagnosis**
Pass the Scout's findings to `doctor` for root cause analysis. The Doctor
must cite specific kubectl evidence and determine severity.

**Phase 3 -- Safety check**
Review the Doctor's diagnosis and recommended action:
- If severity is CRITICAL or the action is destructive (rollback, delete
  in production, resource changes), clearly note that approval is required.
- If the action is safe and non-destructive (restarting a crashing pod
  in a non-production namespace), you may proceed.

**Phase 4 -- Remediation**
Delegate to `executor` with the specific action to perform. The executor
must verify the fix after applying it.

**Phase 5 -- Communication**
Delegate to `comms` to:
- Post a resolution update to Slack (or an ongoing-incident update if
  remediation failed).
- If the incident is resolved, post a post-mortem summary.

### Decision-making rules
1. ALWAYS start with Scout. Never skip reconnaissance.
2. NEVER let Executor act without a Doctor diagnosis first.
3. If the Doctor says evidence is insufficient, send Scout back for more data.
4. If Executor reports failure, route back to Doctor for re-diagnosis
   (maximum 3 retries).
5. Keep Comms updated at each phase transition.
6. If you cannot resolve the incident after 3 attempts, escalate by
   having Comms post an escalation notice.

### Output
After all phases complete, provide a final incident summary including:
- Incident ID
- Root cause
- Actions taken
- Final status (resolved / escalated)
- Duration
"""

# ---------------------------------------------------------------------------
# LLM for the supervisor
# ---------------------------------------------------------------------------

_model_name = settings.LITELLM_MODEL_REASONING.removeprefix("anthropic/")

_llm = ChatAnthropic(
    model=_model_name,
    max_tokens=8192,
    anthropic_api_key=settings.LLM_API_KEY or None,
)

# ---------------------------------------------------------------------------
# Build the supervisor graph
# ---------------------------------------------------------------------------

_checkpointer = MemorySaver()

commander_graph = create_supervisor(
    agents=[scout_agent, doctor_agent, executor_agent, comms_agent],
    model=_llm,
    prompt=COMMANDER_SYSTEM_PROMPT,
    output_mode="full_history",
).compile(checkpointer=_checkpointer)


# ---------------------------------------------------------------------------
# Convenience runner
# ---------------------------------------------------------------------------


async def run_incident_response(description: str) -> dict[str, Any]:
    """Run the full incident response pipeline for a given incident description.

    Parameters
    ----------
    description:
        A human-readable description of the incident or alert that triggered
        the response (e.g. "Pods in namespace demo are CrashLoopBackOff").

    Returns
    -------
    dict
        The full conversation history and final state from the supervisor graph.
    """
    incident_id = f"inc-{uuid.uuid4().hex[:8]}"
    thread_id = f"thread-{uuid.uuid4().hex[:8]}"

    config = {"configurable": {"thread_id": thread_id}}

    initial_message = {
        "messages": [
            {
                "role": "user",
                "content": (
                    f"INCIDENT REPORT [{incident_id}]\n\n"
                    f"{description}\n\n"
                    f"Please follow the incident response protocol. "
                    f"Start with reconnaissance, then diagnose, remediate, "
                    f"and communicate the outcome."
                ),
            }
        ],
    }

    logger.info(
        "Starting incident response: id=%s, thread=%s",
        incident_id,
        thread_id,
    )

    result = await commander_graph.ainvoke(initial_message, config=config)

    logger.info("Incident response complete: id=%s", incident_id)

    return {
        "incident_id": incident_id,
        "thread_id": thread_id,
        "result": result,
    }
