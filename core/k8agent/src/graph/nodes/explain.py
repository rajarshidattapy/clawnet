"""Explain node — generates a plain-English incident summary and audit log."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from core.k8agent.src.config import settings
from core.k8agent.src.graph.state import ClusterState
from core.k8agent.src.knowledge.fingerprint import compute_fingerprint
from core.k8agent.src.knowledge.runbook_store import store_runbook
from core.k8agent.src.llm.client import llm_call_sync, set_current_trace_id
from core.k8agent.src.llm.prompts import EXPLAINER_SYSTEM_PROMPT
from core.k8agent.src.blockchain.stellar_client import store_incident_on_chain
from core.k8agent.src.mcp_server.slack_tools import send_slack_message
from core.k8agent.src.models import LogEntry
from core.k8agent.src.utils.audit import write_audit_entry

logger = logging.getLogger(__name__)


def _markdown_to_slack(md: str) -> str:
    """Convert Markdown to Slack mrkdwn format."""
    import re
    text = md
    # Headers: # Title -> *Title*
    text = re.sub(r'^#{1,3}\s+(.+)$', r'*\1*', text, flags=re.MULTILINE)
    # Bold: **text** -> *text*
    text = re.sub(r'\*\*(.+?)\*\*', r'*\1*', text)
    # Inline code already works in Slack (`code`)
    # Links: [text](url) -> <url|text>
    text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<\2|\1>', text)
    # Remove --- dividers
    text = re.sub(r'^-{3,}$', '', text, flags=re.MULTILINE)
    # Clean up extra blank lines
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def explain_node(state: ClusterState) -> dict:
    """Generate incident summary, write audit log, and post to Slack.

    Returns ``{"audit_log": [LogEntry]}``.
    """
    anomalies = state.get("anomalies", [])
    idx = state.get("current_anomaly_index", 0)
    anomaly = anomalies[idx] if anomalies and idx < len(anomalies) else {}
    diagnosis = state.get("diagnosis", "N/A")
    plan = state.get("plan") or {}
    result = state.get("result", "N/A")
    approved = state.get("approved", True)
    incident_id = state.get("incident_id", "unknown")

    # Set trace context for LLM call
    if incident_id:
        set_current_trace_id(incident_id, stage="explain")

    # ── Generate explanation via LLM ─────────────────────────────────
    user_message = (
        f"Incident ID: {incident_id}\n"
        f"Anomaly: {json.dumps(anomaly, default=str)}\n"
        f"Diagnosis: {diagnosis}\n"
        f"Plan: {json.dumps(plan, default=str)}\n"
        f"Approved: {approved}\n"
        f"Execution Result: {result}"
    )

    messages = [
        {"role": "system", "content": EXPLAINER_SYSTEM_PROMPT},
        {"role": "user", "content": user_message},
    ]

    summary = llm_call_sync(messages)

    if not summary:
        summary = (
            f"Incident {incident_id}: {anomaly.get('type', 'Unknown')} on "
            f"{anomaly.get('affected_resource', 'unknown')}. "
            f"Action: {plan.get('action', 'N/A')}. Result: {result}."
        )

    # ── Build audit log entry ────────────────────────────────────────
    now = datetime.now(timezone.utc).isoformat()
    result_str = state.get("result", "")

    if not approved and not result_str:
        # HITL rejected — no execution happened
        decision = "rejected"
        result = "rejected: human operator declined the remediation"
    elif result_str:
        decision = "human-approved" if approved else "auto-executed"
    else:
        decision = "auto-executed"

    log_entry = LogEntry(
        incident_id=incident_id,
        timestamp=now,
        stage="explain",
        summary=summary,
        details={
            "anomaly": anomaly,
            "diagnosis": diagnosis,
            "plan": plan,
            "stage_timings": state.get("stage_timings", {}),
        },
        decision=decision,
        outcome=result,
    )

    write_audit_entry(log_entry)

    # ── Store runbook for future use ────────────────────────────────
    if settings.ENABLE_RUNBOOK_CACHE:
        try:
            if anomaly and result:
                fp = compute_fingerprint(anomaly["type"], anomaly.get("raw_signal", ""), "Pod")
                success = "success" in result.lower() or "deleted" in result.lower()
                store_runbook(fp, state.get("diagnosis", ""), json.dumps(plan) if plan else "", success, 0)
        except Exception as e:
            logger.warning("Failed to store runbook: %s", e)

    # ── Store on blockchain (if enabled) ────────────────────────────
    if settings.ENABLE_BLOCKCHAIN and settings.STELLAR_CONTRACT_ID and len(settings.STELLAR_CONTRACT_ID) > 10:
        import threading

        def _store_blockchain() -> None:
            try:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(
                    store_incident_on_chain(
                        incident_id=incident_id,
                        anomaly_type=anomaly.get("type", "unknown"),
                        action_taken=plan.get("action", "N/A"),
                        timestamp=int(datetime.now(timezone.utc).timestamp()),
                        confidence_score=int(plan.get("confidence", 0) * 100),
                        was_auto_executed=(decision == "auto-executed"),
                        diagnosis_summary=diagnosis[:256] if diagnosis else "N/A",
                    )
                )
                loop.close()
                logger.info("Blockchain record stored for incident %s", incident_id)
            except Exception:
                logger.exception("Blockchain storage failed (non-fatal)")

        t = threading.Thread(target=_store_blockchain, daemon=True)
        t.start()
        logger.info("Blockchain storage thread started for %s", incident_id)

    # ── Create GitHub PR for permanent fix (if applicable) ─────────
    if plan.get("action") in ("patch_deployment_resources", "rollback_deployment") and "success" in result.lower():
        import threading

        def _create_pr():
            try:
                from core.k8agent.src.github_pr import create_config_fix_pr
                pr_result = create_config_fix_pr(
                    incident_id=incident_id,
                    deployment_name=plan.get("target", "unknown"),
                    namespace=plan.get("namespace", "k8swhisperer-demo"),
                    action=plan.get("action", ""),
                    params=plan.get("params", {}),
                    diagnosis=diagnosis[:500] if diagnosis else "N/A",
                )
                logger.info("GitHub PR result: %s", pr_result.get("status"))
            except Exception:
                logger.exception("GitHub PR creation failed (non-fatal)")

        t = threading.Thread(target=_create_pr, daemon=True)
        t.start()
        logger.info("GitHub PR creation thread started for %s", incident_id)

    # ── Post to Slack (Block Kit formatted) ───────────────────────────
    channel = settings.SLACK_CHANNEL_ID
    if channel:
        try:
            slack_text = _markdown_to_slack(summary)
            severity = anomaly.get("severity", "MED")
            emoji = {"CRITICAL": ":rotating_light:", "HIGH": ":warning:", "MED": ":large_yellow_circle:", "LOW": ":white_check_mark:"}.get(severity, ":memo:")
            outcome_emoji = ":white_check_mark:" if "success" in result.lower() else ":x:" if "failure" in result.lower() else ":hourglass:"

            blocks = [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"{emoji} Incident {incident_id[:12]} — {anomaly.get('type', 'Unknown')}", "emoji": True},
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Resource:*\n`{anomaly.get('affected_resource', 'N/A')}`"},
                        {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                        {"type": "mrkdwn", "text": f"*Action:*\n`{plan.get('action', 'N/A')}`"},
                        {"type": "mrkdwn", "text": f"*Decision:*\n{decision}"},
                    ],
                },
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": slack_text[:2900]},
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"{outcome_emoji} *Outcome:* {result[:200]}"},
                    ],
                },
            ]

            send_slack_message(channel=channel, text=f"Incident {incident_id}: {anomaly.get('type', 'Unknown')}", blocks=blocks)
            logger.info("Posted incident summary to Slack channel %s", channel)
        except Exception:
            logger.exception("Failed to post summary to Slack")
    else:
        logger.warning("SLACK_CHANNEL_ID not set; skipping Slack post")

    logger.info("explain_node complete for incident %s", incident_id)
    return {"audit_log": [log_entry]}
