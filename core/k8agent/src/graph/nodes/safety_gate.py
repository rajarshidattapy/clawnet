"""Safety gate — conditional routing function for the LangGraph.

This is a pure function (NOT a node). It is used as a conditional edge
router to decide whether to auto-execute or require human approval.
"""

from __future__ import annotations

import logging

from core.k8agent.src.graph.state import ClusterState
from core.k8agent.src.models import DESTRUCTIVE_ACTIONS

logger = logging.getLogger(__name__)


def safety_router(state: ClusterState) -> str:
    """Route to ``"execute"`` or ``"hitl_node"`` based on plan risk.

    Auto-execute criteria (ALL must be true):
    - plan.confidence > 0.8
    - plan.blast_radius == "low"
    - plan.action not in DESTRUCTIVE_ACTIONS

    Otherwise route to human-in-the-loop approval.
    """
    plan = state.get("plan")
    if plan is None:
        logger.warning("safety_router: no plan in state; routing to hitl_node")
        return "hitl_node"

    confidence = plan.get("confidence", 0.0)
    blast_radius = plan.get("blast_radius", "high")
    action = plan.get("action", "")

    auto_execute = (
        confidence > 0.8
        and blast_radius == "low"
        and action not in DESTRUCTIVE_ACTIONS
    )

    decision = "execute" if auto_execute else "hitl_node"

    logger.info(
        "safety_router: confidence=%.2f, blast_radius=%s, action=%s, "
        "destructive=%s -> %s",
        confidence,
        blast_radius,
        action,
        action in DESTRUCTIVE_ACTIONS,
        decision,
    )
    return decision
