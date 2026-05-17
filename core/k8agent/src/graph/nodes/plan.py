"""Plan node — generates a remediation plan for the diagnosed anomaly."""

from __future__ import annotations

import asyncio
import json
import logging

from core.k8agent.src.graph.state import ClusterState
from core.k8agent.src.llm.client import llm_call_json_sync, set_current_trace_id
from core.k8agent.src.llm.prompts import PLANNER_SYSTEM_PROMPT
from core.k8agent.src.models import RemediationPlan
from core.k8agent.src.utils.audit import make_entry, write_audit_entry

logger = logging.getLogger(__name__)

ALLOWED_ACTIONS = frozenset({
    "delete_pod", "patch_deployment_resources", "rollback_deployment",
    "scale_deployment", "no_op", "cordon_node",
})

# ── Hardcoded fallback plans per anomaly type ────────────────────────────

_FALLBACK_PLANS: dict[str, dict] = {
    "CrashLoopBackOff": {
        "action": "delete_pod",
        "params": {},
        "confidence": 0.5,
        "blast_radius": "low",
        "is_destructive": False,
        "reasoning": "Restart the pod to clear transient crash state.",
    },
    "OOMKilled": {
        "action": "patch_deployment_resources",
        "params": {"memory_limit": "+50%"},
        "confidence": 0.75,
        "blast_radius": "medium",
        "is_destructive": False,
        "reasoning": "Increase memory limit to prevent OOMKill. Routes to HITL — resource changes affect all pods in the deployment.",
    },
    "ImagePullBackOff": {
        "action": "no_op",
        "params": {},
        "confidence": 0.3,
        "blast_radius": "low",
        "is_destructive": False,
        "reasoning": "Image pull issue requires manual image fix; no safe auto-remediation.",
    },
    "Pending": {
        "action": "no_op",
        "params": {},
        "confidence": 0.3,
        "blast_radius": "medium",
        "is_destructive": False,
        "reasoning": "Scheduling failure likely needs node capacity or resource adjustment. Routes to HITL for human review.",
    },
    "Evicted": {
        "action": "delete_pod",
        "params": {},
        "confidence": 0.5,
        "blast_radius": "low",
        "is_destructive": False,
        "reasoning": "Recreate evicted pod; node pressure may have cleared.",
    },
    "CPUThrottling": {
        "action": "patch_deployment_resources",
        "params": {"cpu_limit": "1000m"},
        "confidence": 0.7,
        "blast_radius": "medium",
        "is_destructive": False,
        "reasoning": "Increase CPU limits to reduce throttling. Routes to HITL due to medium blast radius.",
    },
    "DeploymentStalled": {
        "action": "rollback_deployment",
        "params": {},
        "confidence": 0.7,
        "blast_radius": "high",
        "is_destructive": True,
        "reasoning": "Rollback to last known good revision. Destructive action requires human approval.",
    },
    "NodeNotReady": {
        "action": "cordon_node",
        "params": {},
        "confidence": 0.5,
        "blast_radius": "high",
        "is_destructive": True,
        "reasoning": "Cordon node to prevent new scheduling. High blast radius requires human approval.",
    },
}


def _build_fallback(anomaly: dict) -> RemediationPlan:
    """Build a safe fallback plan when the LLM fails."""
    atype = anomaly.get("type", "Unknown")
    defaults = _FALLBACK_PLANS.get(atype, {
        "action": "no_op",
        "params": {},
        "confidence": 0.2,
        "blast_radius": "low",
        "is_destructive": False,
        "reasoning": f"Fallback: no automatic remediation for {atype}.",
    })
    return RemediationPlan(
        action=defaults["action"],
        target=anomaly.get("affected_resource", "unknown"),
        namespace=anomaly.get("namespace", "k8swhisperer-demo"),
        params=defaults["params"],
        confidence=defaults["confidence"],
        blast_radius=defaults["blast_radius"],
        is_destructive=defaults["is_destructive"],
        reasoning=defaults["reasoning"],
    )


def plan_node(state: ClusterState) -> dict:
    """Generate a remediation plan for the current anomaly.

    Returns ``{"plan": RemediationPlan}``.
    """
    anomalies = state.get("anomalies", [])
    idx = state.get("current_anomaly_index", 0)
    diagnosis = state.get("diagnosis", "")

    if not anomalies or idx >= len(anomalies):
        logger.warning("plan_node: no anomaly to plan for")
        return {"plan": None}

    anomaly = anomalies[idx]
    logger.info("plan_node: planning for %s on %s", anomaly.get("type"), anomaly.get("affected_resource"))

    # Set trace context for LLM call
    incident_id = state.get("incident_id", "")
    if incident_id:
        set_current_trace_id(incident_id, stage="plan")

    user_message = (
        f"Anomaly: {json.dumps(anomaly, default=str)}\n\n"
        f"Diagnosis: {diagnosis}"
    )

    messages = [
        {"role": "system", "content": PLANNER_SYSTEM_PROMPT},
        {"role": "user", "content": user_message},
    ]

    raw_plan = llm_call_json_sync(messages)

    if not isinstance(raw_plan, dict) or "action" not in raw_plan:
        logger.warning("Planner LLM returned invalid plan; using fallback")
        plan = _build_fallback(anomaly)
    else:
        # Validate action
        action = raw_plan.get("action", "no_op")
        if action not in ALLOWED_ACTIONS:
            logger.warning("LLM proposed disallowed action: %s, falling back", action)
            plan = _build_fallback(anomaly)
        else:
            # Clamp confidence to [0.0, 1.0]
            confidence = float(raw_plan.get("confidence", 0.5))
            confidence = max(0.0, min(1.0, confidence))

            # Validate blast_radius
            blast_radius = raw_plan.get("blast_radius", "high")
            if blast_radius not in ("low", "medium", "high"):
                blast_radius = "high"

            # Enforce minimum blast_radius per anomaly type (PS requirements)
            # LLM cannot downgrade these — they MUST route to HITL
            _MIN_BLAST = {
                "Pending": "medium",
                "ImagePullBackOff": "medium",
                "CPUThrottling": "medium",
                "DeploymentStalled": "high",
                "NodeNotReady": "high",
            }
            _BLAST_ORDER = {"low": 0, "medium": 1, "high": 2}
            min_blast = _MIN_BLAST.get(anomaly.get("type", ""), "low")
            if _BLAST_ORDER.get(blast_radius, 0) < _BLAST_ORDER.get(min_blast, 0):
                logger.info(
                    "Enforcing minimum blast_radius %s for %s (LLM proposed %s)",
                    min_blast, anomaly.get("type"), blast_radius,
                )
                blast_radius = min_blast

            # Prevent cross-namespace attacks: use anomaly's namespace
            anomaly_ns = anomaly.get("namespace", "k8swhisperer-demo")
            proposed_ns = raw_plan.get("namespace", anomaly_ns)
            if proposed_ns != anomaly_ns:
                logger.warning(
                    "LLM proposed namespace %s but anomaly is in %s; using anomaly namespace",
                    proposed_ns, anomaly_ns,
                )
                proposed_ns = anomaly_ns

            plan = RemediationPlan(
                action=action,
                target=raw_plan.get("target", anomaly.get("affected_resource", "unknown")),
                namespace=proposed_ns,
                params=raw_plan.get("params", {}),
                confidence=confidence,
                blast_radius=blast_radius,
                is_destructive=bool(raw_plan.get("is_destructive", False)),
                reasoning=raw_plan.get("reasoning", ""),
            )

    logger.info("plan_node result: action=%s, confidence=%.2f", plan["action"], plan["confidence"])

    # Write audit entry for the plan stage
    if incident_id:
        write_audit_entry(make_entry(
            incident_id=incident_id,
            stage="plan",
            summary=f"Plan: {plan['action']} on {plan['target']} (confidence={plan['confidence']:.2f}, blast_radius={plan['blast_radius']})",
            details={"plan": dict(plan), "anomaly": anomaly},
        ))

    return {"plan": plan}
