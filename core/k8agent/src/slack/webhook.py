"""FastAPI router for Slack interactive webhook (block_actions)."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from typing import Any

import httpx
from fastapi import APIRouter, BackgroundTasks, Form, Header, HTTPException, Request
from langgraph.types import Command

from core.k8agent.src.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/slack", tags=["slack"])


# ── Signature verification ──────────────────────────────────────────────────


def _verify_signature(
    body: bytes,
    timestamp: str,
    signature: str,
) -> bool:
    """Verify Slack request signature using HMAC-SHA256.

    Slack signs every request with ``v0={hmac_sha256(signing_secret, "v0:{ts}:{body}")}``.
    """
    if not settings.SLACK_SIGNING_SECRET:
        logger.warning("SLACK_SIGNING_SECRET is not set — skipping verification")
        return True

    # Reject requests older than 5 minutes to prevent replay attacks
    if abs(time.time() - int(timestamp)) > 60 * 5:
        return False

    base = f"v0:{timestamp}:{body.decode('utf-8')}"
    computed = (
        "v0="
        + hmac.new(
            settings.SLACK_SIGNING_SECRET.encode("utf-8"),
            base.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
    )
    return hmac.compare_digest(computed, signature)


# ── Background processing ──────────────────────────────────────────────────


async def _resume_graph(
    thread_id: str,
    approved: bool,
    username: str,
    response_url: str,
) -> None:
    """Resume the LangGraph pipeline and update the Slack message."""
    # Import graph lazily to avoid circular imports at module load time
    from core.k8agent.src.graph.builder import graph

    decision_text = "approved" if approved else "rejected"

    try:
        config: dict[str, Any] = {"configurable": {"thread_id": thread_id}}
        graph.invoke(
            Command(resume={"approved": approved, "user": username}),
            config=config,
        )
        logger.info(
            "Graph resumed for thread %s — %s by %s",
            thread_id,
            decision_text,
            username,
        )
    except Exception:
        logger.exception("Failed to resume graph for thread %s", thread_id)

    # Notify Slack via response_url (ephemeral update)
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                response_url,
                json={
                    "replace_original": True,
                    "text": f":memo: Remediation *{decision_text}* by *{username}*.",
                },
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
    except Exception:
        logger.warning("Failed to update Slack message via response_url", exc_info=True)


# ── Endpoint ────────────────────────────────────────────────────────────────


@router.post("/actions")
async def slack_actions(
    request: Request,
    background_tasks: BackgroundTasks,
    payload: str = Form(...),
    x_slack_request_timestamp: str = Header("", alias="X-Slack-Request-Timestamp"),
    x_slack_signature: str = Header("", alias="X-Slack-Signature"),
) -> dict[str, str]:
    """Handle Slack interactive component callbacks (block_actions).

    Must return 200 within 3 seconds — heavy work is offloaded to a
    ``BackgroundTask``.
    """
    # Read raw body for signature verification
    raw_body = await request.body()
    if not _verify_signature(raw_body, x_slack_request_timestamp, x_slack_signature):
        raise HTTPException(status_code=403, detail="Invalid Slack signature")

    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Malformed payload")

    # Extract action details
    actions = data.get("actions", [])
    if not actions:
        return {"ok": "no actions"}

    action = actions[0]
    action_id = action.get("action_id", "")  # "approve" or "reject"

    try:
        value = json.loads(action.get("value", "{}"))
    except json.JSONDecodeError:
        value = {}

    thread_id = value.get("thread_id", "")
    username = data.get("user", {}).get("username", "unknown")
    response_url = data.get("response_url", "")

    approved = action_id == "approve"
    incident_id = value.get("incident_id", "")

    logger.info(
        "Slack action received: action=%s user=%s thread=%s incident=%s",
        action_id,
        username,
        thread_id,
        incident_id,
    )

    # Offload graph resumption to background
    background_tasks.add_task(
        _resume_graph,
        thread_id=thread_id,
        approved=approved,
        username=username,
        response_url=response_url,
    )

    # Immediate acknowledgement — Slack requires < 3 s response
    return {"ok": "processing"}
