"""Human-in-the-loop node — sends Slack approval request and pauses the graph."""

from __future__ import annotations

import json
import logging
import time

from langgraph.types import interrupt

from core.k8agent.src.config import settings
from core.k8agent.src.graph.state import ClusterState
from core.k8agent.src.mcp_server.slack_tools import send_approval_request

logger = logging.getLogger(__name__)

# Track pending HITL approvals to prevent duplicate Slack messages.
# Key: (anomaly_type, resource) -> {"thread_id", "incident_id", "sent_at"}
_pending_approvals: dict[tuple[str, str], dict] = {}
_PENDING_EXPIRY_SECONDS = 600  # 10 minutes


def is_pending_approval(anomaly_type: str, resource: str) -> bool:
    """Check if an approval is already pending for this anomaly+resource."""
    key = (anomaly_type, resource)
    if key in _pending_approvals:
        sent_at = _pending_approvals[key].get("sent_at", 0)
        if time.time() - sent_at < _PENDING_EXPIRY_SECONDS:
            return True
        # Expired — remove
        del _pending_approvals[key]
    return False


def clear_pending_approval(anomaly_type: str, resource: str) -> None:
    """Clear a pending approval after it's been resolved."""
    key = (anomaly_type, resource)
    _pending_approvals.pop(key, None)


def hitl_node(state: ClusterState) -> dict:
    """Send an approval request to Slack and pause execution.

    The ``interrupt()`` call suspends the LangGraph thread.  When the
    Slack interaction webhook receives an Approve/Reject button click,
    it resumes the thread with ``{"approved": True/False}``.

    Returns ``{"approved": bool}``.
    """
    plan = state.get("plan")
    incident_id = state.get("incident_id", "unknown")
    thread_id = state.get("thread_id", "")

    if plan is None:
        logger.warning("hitl_node: no plan in state")
        return {"approved": False}

    # Check if an approval is already pending for this resource
    anomalies = state.get("anomalies", [])
    idx = state.get("current_anomaly_index", 0)
    anomaly = anomalies[idx] if anomalies and idx < len(anomalies) else {}
    anomaly_type = anomaly.get("type", "unknown")
    resource = anomaly.get("affected_resource", plan.get("target", "unknown"))

    if is_pending_approval(anomaly_type, resource):
        logger.info(
            "hitl_node: approval already pending for %s on %s — skipping duplicate Slack message",
            anomaly_type, resource,
        )
        # Still interrupt to pause the graph, but don't send another Slack message
        response = interrupt(
            {
                "type": "approval_required",
                "incident_id": incident_id,
                "plan": json.loads(json.dumps(plan, default=str)),
                "note": "duplicate — approval already pending in Slack",
            }
        )
        approved = response.get("approved", False) if isinstance(response, dict) else False
        if approved:
            clear_pending_approval(anomaly_type, resource)
        return {"approved": approved}

    plan_summary = (
        f"Action: {plan.get('action', 'N/A')}\n"
        f"Target: {plan.get('target', 'N/A')}\n"
        f"Namespace: {plan.get('namespace', 'N/A')}\n"
        f"Confidence: {plan.get('confidence', 0):.0%}\n"
        f"Blast radius: {plan.get('blast_radius', 'N/A')}\n"
        f"Destructive: {plan.get('is_destructive', False)}\n"
        f"Reasoning: {plan.get('reasoning', 'N/A')}"
    )

    # Send Slack approval request
    channel = settings.SLACK_CHANNEL_ID
    if channel:
        try:
            slack_result = send_approval_request(
                channel=channel,
                incident_id=incident_id,
                plan_summary=plan_summary,
                thread_id=thread_id,
            )
            logger.info("Slack approval request sent: %s", slack_result)

            # Track this as pending
            _pending_approvals[(anomaly_type, resource)] = {
                "thread_id": thread_id,
                "incident_id": incident_id,
                "sent_at": time.time(),
            }
        except Exception:
            logger.exception("Failed to send Slack approval request")
    else:
        logger.warning("SLACK_CHANNEL_ID not configured; skipping Slack notification")

    # Pause the graph and wait for human decision
    logger.info("hitl_node: pausing graph for approval (incident_id=%s)", incident_id)
    response = interrupt(
        {
            "type": "approval_required",
            "incident_id": incident_id,
            "plan": json.loads(json.dumps(plan, default=str)),
            "plan_summary": plan_summary,
        }
    )

    approved = response.get("approved", False) if isinstance(response, dict) else False
    logger.info("hitl_node: received response approved=%s", approved)

    # Clear the pending tracking
    clear_pending_approval(anomaly_type, resource)

    return {"approved": approved}
