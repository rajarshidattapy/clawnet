"""Skill: generate a structured post-mortem report using an LLM.

Produces a Markdown document covering Summary, Timeline, Root Cause,
Impact, Resolution, and Prevention sections based on the incident data.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from core.k8agent.src.llm.client import llm_call
from core.k8agent.src.skills.registry import skills_registry

logger = logging.getLogger(__name__)

_POSTMORTEM_SYSTEM_PROMPT = """\
You are the K8sWhisperer Post-Mortem Writer.

Given structured incident data (anomaly, diagnosis, remediation plan, and
outcome), produce a professional post-mortem report in Markdown.

### Required sections

1. **Summary** - 2-3 sentence executive overview.
2. **Timeline** - Chronological bullet list of key events with timestamps.
3. **Root Cause** - Technical explanation of why the incident occurred.
4. **Impact** - What was affected, for how long, and severity.
5. **Resolution** - What actions were taken and their results.
6. **Prevention** - Concrete recommendations to prevent recurrence.

### Rules
- Be concise but thorough.
- Use clear headings (## level).
- Include any relevant resource names, namespaces, metrics.
- Write for an audience of SREs and engineering managers.
- Output ONLY the Markdown document, no fences wrapping the whole thing.
"""


@skills_registry.skill(
    name="generate_postmortem",
    description=(
        "Generate a structured Markdown post-mortem report for a "
        "resolved incident using LLM analysis."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "incident_id": {"type": "string"},
            "anomaly": {"type": "object"},
            "diagnosis": {"type": "string"},
            "plan": {"type": "object"},
            "result": {"type": "string"},
        },
        "required": ["incident_id", "anomaly", "diagnosis", "plan", "result"],
    },
    output_schema={
        "type": "object",
        "properties": {
            "postmortem_md": {"type": "string"},
        },
    },
)
async def generate_postmortem(
    incident_id: str,
    anomaly: dict,
    diagnosis: str,
    plan: dict,
    result: str,
) -> str:
    """Generate a structured Markdown post-mortem for a resolved incident.

    Parameters
    ----------
    incident_id:
        Unique identifier for the incident.
    anomaly:
        The original anomaly dict (type, severity, affected_resource, etc.).
    diagnosis:
        The root-cause diagnosis text.
    plan:
        The remediation plan dict (action, target, params, etc.).
    result:
        The outcome of the remediation (success/failure description).

    Returns
    -------
    str
        A complete Markdown post-mortem document.
    """
    now = datetime.now(timezone.utc).isoformat()

    user_content = (
        f"## Incident Data\n\n"
        f"**Incident ID:** {incident_id}\n"
        f"**Generated at:** {now}\n\n"
        f"### Anomaly\n"
        f"- **Type:** {anomaly.get('type', 'unknown')}\n"
        f"- **Severity:** {anomaly.get('severity', 'unknown')}\n"
        f"- **Affected Resource:** {anomaly.get('affected_resource', 'unknown')}\n"
        f"- **Namespace:** {anomaly.get('namespace', 'unknown')}\n"
        f"- **Confidence:** {anomaly.get('confidence', 'N/A')}\n"
        f"- **Raw Signal:** {anomaly.get('raw_signal', 'N/A')}\n"
        f"- **First Detected:** {anomaly.get('timestamp', 'unknown')}\n\n"
        f"### Diagnosis\n{diagnosis}\n\n"
        f"### Remediation Plan\n"
        f"- **Action:** {plan.get('action', 'unknown')}\n"
        f"- **Target:** {plan.get('target', 'unknown')}\n"
        f"- **Namespace:** {plan.get('namespace', 'unknown')}\n"
        f"- **Parameters:** {plan.get('params', {})}\n"
        f"- **Blast Radius:** {plan.get('blast_radius', 'unknown')}\n"
        f"- **Destructive:** {plan.get('is_destructive', False)}\n"
        f"- **Reasoning:** {plan.get('reasoning', 'N/A')}\n\n"
        f"### Outcome\n{result}\n"
    )

    messages = [
        {"role": "system", "content": _POSTMORTEM_SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]

    postmortem_md = await llm_call(messages, temperature=0.3)

    logger.info("Generated post-mortem for incident %s", incident_id)

    return postmortem_md
