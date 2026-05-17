"""Communications Agent -- incident communication specialist.

Manages incident communications: posts status updates to Slack,
creates post-mortem summaries, and keeps stakeholders informed.
Uses Sonnet (fast model) for quick message composition.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from langchain_anthropic import ChatAnthropic
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

from core.k8agent.src.config import settings
from core.k8agent.src.mcp_server.slack_tools import send_slack_message as _send_slack_message

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LangChain tool wrappers
# ---------------------------------------------------------------------------


@tool
async def send_slack_message_tool(
    channel: str,
    text: str,
) -> str:
    """Send a message to a Slack channel. Use for incident updates and post-mortems."""
    try:
        result = _send_slack_message(channel=channel, text=text)
        return json.dumps(result, default=str)
    except Exception as exc:
        logger.exception("send_slack_message_tool failed")
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

COMMS_SYSTEM_PROMPT = """\
You are a Kubernetes Communications agent -- responsible for keeping
stakeholders informed during and after incident response.

### Responsibilities
1. **Incident updates** -- Post clear, concise status updates to the
   designated Slack channel as the incident progresses.
2. **Post-mortems** -- After resolution, compose a structured post-mortem
   summary covering:
   - What happened (symptoms)
   - Root cause
   - Actions taken
   - Resolution status
   - Preventive recommendations
3. **Audience awareness** -- Write for a mixed audience of SREs and
   non-technical stakeholders. Avoid unnecessary jargon; explain
   Kubernetes terms briefly when used.

### Message formatting
- Use Slack mrkdwn formatting (*bold*, _italic_, `code`).
- Keep updates under 200 words.
- Use bullet points for clarity.
- Include severity level and affected services.
- Timestamp each update (relative: "5 minutes ago", "just now").

### Channel
Use the configured channel ID from the incident context. If no channel
is specified, use the default channel.

### Rules
- NEVER post sensitive data (secrets, tokens, credentials) in messages.
- NEVER post raw kubectl output -- summarise it.
- Be factual and calm in tone. Avoid speculation.
- If the incident is ongoing, clearly state "ONGOING" in the update.
- If resolved, state "RESOLVED" and include next steps.
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

comms_agent = create_react_agent(
    model=_llm,
    tools=[send_slack_message_tool],
    prompt=COMMS_SYSTEM_PROMPT,
    name="comms",
)
