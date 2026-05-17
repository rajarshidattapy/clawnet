"""FastMCP server exposing Slack messaging tools via the slack-sdk."""

from __future__ import annotations

import json
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from core.k8agent.src.config import settings

logger = logging.getLogger(__name__)

mcp_server = FastMCP(name="slack-tools")

_slack: WebClient | None = None


def _get_slack() -> WebClient:
    """Lazy-init the Slack WebClient."""
    global _slack
    if _slack is None:
        _slack = WebClient(token=settings.SLACK_BOT_TOKEN)
    return _slack


def _error(msg: str, exc: Exception | None = None) -> dict[str, Any]:
    d: dict[str, Any] = {"error": msg}
    if exc:
        d["detail"] = str(exc)
    return d


@mcp_server.tool()
def send_slack_message(
    channel: str,
    text: str,
    blocks: list | None = None,
) -> dict:
    """Send a message (with optional Block Kit blocks) to a Slack channel."""
    try:
        client = _get_slack()
        kwargs: dict[str, Any] = {"channel": channel, "text": text}
        if blocks:
            kwargs["blocks"] = blocks
        resp = client.chat_postMessage(**kwargs)
        return {
            "ok": resp["ok"],
            "channel": resp["channel"],
            "ts": resp["ts"],
        }
    except SlackApiError as exc:
        logger.exception("send_slack_message failed")
        return _error("Slack API error", exc)
    except Exception as exc:
        logger.exception("send_slack_message unexpected error")
        return _error("Failed to send Slack message", exc)


@mcp_server.tool()
def send_approval_request(
    channel: str,
    incident_id: str,
    plan_summary: str,
    thread_id: str,
) -> dict:
    """Send a Block Kit approval request with Approve / Reject buttons.

    The buttons carry the *incident_id* as their ``value`` so the Slack
    interaction handler can resume the correct LangGraph thread.
    """
    button_value = json.dumps({"thread_id": thread_id, "incident_id": incident_id})

    # Parse plan_summary lines into structured fields
    fields = []
    for line in plan_summary.strip().split("\n"):
        line = line.strip()
        if ":" in line:
            key, val = line.split(":", 1)
            fields.append({"type": "mrkdwn", "text": f"*{key.strip()}:*\n{val.strip()}"})

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": ":rotating_light: Approval Required",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f":label: *Incident:* `{incident_id}`",
            },
        },
    ]

    # Add fields in pairs (Slack allows max 10 fields per section)
    if fields:
        for i in range(0, len(fields), 2):
            blocks.append({
                "type": "section",
                "fields": fields[i:i+2],
            })

    blocks.extend([
        {"type": "divider"},
        {
            "type": "actions",
            "block_id": f"approval_{incident_id}",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": ":white_check_mark: Approve", "emoji": True},
                    "style": "primary",
                    "action_id": "approve",
                    "value": button_value,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": ":x: Reject", "emoji": True},
                    "style": "danger",
                    "action_id": "reject",
                    "value": button_value,
                },
            ],
        },
    ])

    fallback_text = f"Approval required for incident {incident_id}: {plan_summary}"

    try:
        client = _get_slack()
        kwargs: dict[str, Any] = {
            "channel": channel,
            "text": fallback_text,
            "blocks": blocks,
        }
        # NOTE: thread_id here is the LangGraph thread ID (for graph resumption),
        # not a Slack message timestamp.  Do not use it as thread_ts.

        resp = client.chat_postMessage(**kwargs)
        return {
            "ok": resp["ok"],
            "channel": resp["channel"],
            "ts": resp["ts"],
            "incident_id": incident_id,
        }
    except SlackApiError as exc:
        logger.exception("send_approval_request Slack API error")
        return _error("Slack API error", exc)
    except Exception as exc:
        logger.exception("send_approval_request unexpected error")
        return _error("Failed to send approval request", exc)
