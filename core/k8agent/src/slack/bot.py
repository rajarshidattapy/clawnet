"""Slack Block Kit message builder for K8sWhisperer incident notifications."""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from core.k8agent.src.config import settings
from core.k8agent.src.models import Anomaly, RemediationPlan

logger = logging.getLogger(__name__)

_client: Optional[WebClient] = None


def _get_client() -> WebClient:
    """Return a lazily-initialised Slack WebClient."""
    global _client
    if _client is None:
        _client = WebClient(token=settings.SLACK_BOT_TOKEN)
    return _client


# ── Public API ─────────────────────────────────────────────────────────────


def send_incident_notification(
    channel: str,
    anomaly: Anomaly,
    diagnosis: str,
) -> Optional[str]:
    """Post a rich incident notification and return the message timestamp.

    Returns the ``ts`` of the posted message (useful for threading), or
    ``None`` if posting fails.
    """
    severity = anomaly.get("severity", "UNKNOWN")
    severity_emoji = {
        "CRITICAL": ":rotating_light:",
        "HIGH": ":warning:",
        "MED": ":large_yellow_circle:",
        "LOW": ":information_source:",
    }.get(severity, ":grey_question:")

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{severity_emoji} K8sWhisperer Incident — {anomaly.get('type', 'Unknown')}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                {"type": "mrkdwn", "text": f"*Resource:*\n{anomaly.get('affected_resource', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Namespace:*\n{anomaly.get('namespace', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Confidence:*\n{anomaly.get('confidence', 0):.0%}"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Signal:*\n```{anomaly.get('raw_signal', 'N/A')}```",
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Diagnosis:*\n{diagnosis}",
            },
        },
    ]

    try:
        response = _get_client().chat_postMessage(
            channel=channel,
            text=f"Incident detected: {anomaly.get('type', 'Unknown')} on {anomaly.get('affected_resource', 'N/A')}",
            blocks=blocks,
        )
        return response.get("ts")
    except SlackApiError:
        logger.warning("Failed to send incident notification to %s", channel, exc_info=True)
        return None


def send_approval_request(
    channel: str,
    incident_id: str,
    plan: RemediationPlan,
    thread_id: str,
) -> Optional[str]:
    """Post a Block Kit approval request with Approve / Reject buttons.

    Returns the message ``ts``, or ``None`` on failure.
    """
    button_value = json.dumps({"thread_id": thread_id, "incident_id": incident_id})

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": ":shield: Remediation Approval Required",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Action:*\n`{plan.get('action', 'N/A')}`"},
                {"type": "mrkdwn", "text": f"*Target:*\n`{plan.get('target', 'N/A')}`"},
                {"type": "mrkdwn", "text": f"*Confidence:*\n{plan.get('confidence', 0):.0%}"},
                {"type": "mrkdwn", "text": f"*Blast Radius:*\n{plan.get('blast_radius', 'N/A')}"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Reasoning:*\n{plan.get('reasoning', 'No reasoning provided.')}",
            },
        },
        {"type": "divider"},
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve", "emoji": True},
                    "style": "primary",
                    "action_id": "approve",
                    "value": button_value,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Reject", "emoji": True},
                    "style": "danger",
                    "action_id": "reject",
                    "value": button_value,
                },
            ],
        },
    ]

    try:
        response = _get_client().chat_postMessage(
            channel=channel,
            text=f"Approval required for {plan.get('action', 'remediation')} on {plan.get('target', 'unknown')}",
            blocks=blocks,
        )
        return response.get("ts")
    except SlackApiError:
        logger.warning("Failed to send approval request to %s", channel, exc_info=True)
        return None


def send_incident_resolved(
    channel: str,
    incident_id: str,
    summary: str,
) -> Optional[str]:
    """Post a resolution summary for a closed incident.

    Returns the message ``ts``, or ``None`` on failure.
    """
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": ":white_check_mark: Incident Resolved",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Incident ID:*\n`{incident_id}`"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Summary:*\n{summary}",
            },
        },
    ]

    try:
        response = _get_client().chat_postMessage(
            channel=channel,
            text=f"Incident {incident_id} resolved: {summary[:100]}",
            blocks=blocks,
        )
        return response.get("ts")
    except SlackApiError:
        logger.warning("Failed to send resolution message to %s", channel, exc_info=True)
        return None


def update_message(
    channel: str,
    ts: str,
    text: str,
) -> None:
    """Update an existing Slack message in-place.

    Silently logs a warning on failure — never raises.
    """
    try:
        _get_client().chat_update(
            channel=channel,
            ts=ts,
            text=text,
        )
    except SlackApiError:
        logger.warning("Failed to update message %s in %s", ts, channel, exc_info=True)
