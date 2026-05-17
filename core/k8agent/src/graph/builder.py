"""Build and compile the K8sWhisperer LangGraph pipeline.

Exports:
    graph       — the compiled StateGraph ready for invocation
    run_pipeline — convenience function to invoke the graph
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Callable

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from core.k8agent.src.graph.nodes.detect import detect_node
from core.k8agent.src.graph.nodes.diagnose import diagnose_node
from core.k8agent.src.graph.nodes.execute import execute_node
from core.k8agent.src.graph.nodes.explain import explain_node
from core.k8agent.src.graph.nodes.hitl import hitl_node
from core.k8agent.src.graph.nodes.observe import observe_node
from core.k8agent.src.graph.nodes.plan import plan_node
from core.k8agent.src.graph.nodes.safety_gate import safety_router
from core.k8agent.src.graph.state import ClusterState

logger = logging.getLogger(__name__)


def _timed(stage_name: str, fn: Callable) -> Callable:
    """Wrap a node function to record execution time in stage_timings."""
    def wrapper(state: ClusterState) -> dict:
        start = time.time()
        result = fn(state)
        elapsed_ms = round((time.time() - start) * 1000)
        timings = {stage_name: elapsed_ms}
        if "stage_timings" not in result:
            result["stage_timings"] = timings
        else:
            result["stage_timings"].update(timings)
        logger.info("Stage %s completed in %dms", stage_name, elapsed_ms)
        return result
    return wrapper

_MAX_RETRIES = 3

# ── Conditional edge helpers ─────────────────────────────────────────────


def _has_anomalies(state: ClusterState) -> str:
    """Route after detect: if anomalies exist, start diagnosis; else finish."""
    anomalies = state.get("anomalies", [])
    if anomalies:
        return "diagnose"
    return END


_retry_tracker: dict[str, int] = {}  # incident_id -> actual retry count

def _verify_check(state: ClusterState) -> str:
    """Route after execute: check result and decide next step.

    - success -> explain
    - failure + retries left -> diagnose (re-diagnose and re-plan)
    - failure + retries exhausted -> explain (report failure)
    """
    result = state.get("result", "")
    incident_id = state.get("incident_id", "")

    if result.startswith("success"):
        _retry_tracker.pop(incident_id, None)
        return "explain"

    # Track retries independently of state (belt + suspenders)
    actual_retries = _retry_tracker.get(incident_id, 0) + 1
    _retry_tracker[incident_id] = actual_retries

    if actual_retries < _MAX_RETRIES:
        logger.info(
            "verify_check: failure (retry %d/%d), routing back to diagnose",
            actual_retries, _MAX_RETRIES,
        )
        return "diagnose"

    logger.warning("verify_check: retries exhausted (%d), routing to explain", actual_retries)
    _retry_tracker.pop(incident_id, None)
    return "explain"


def _hitl_decision(state: ClusterState) -> str:
    """Route after hitl_node: approved -> execute, rejected -> explain."""
    if state.get("approved", False):
        return "execute"
    return "explain"


# ── Graph construction ───────────────────────────────────────────────────


def _build_graph() -> StateGraph:
    """Construct the raw StateGraph (not yet compiled)."""
    builder = StateGraph(ClusterState)

    # Add all nodes (wrapped with timing)
    builder.add_node("observe", _timed("observe", observe_node))
    builder.add_node("detect", _timed("detect", detect_node))
    builder.add_node("diagnose", _timed("diagnose", diagnose_node))
    builder.add_node("plan", _timed("plan", plan_node))
    builder.add_node("execute", _timed("execute", execute_node))
    builder.add_node("hitl_node", _timed("hitl", hitl_node))
    builder.add_node("explain", _timed("explain", explain_node))

    # ── Edges ────────────────────────────────────────────────────────
    builder.add_edge(START, "observe")
    builder.add_edge("observe", "detect")

    # detect -> diagnose (if anomalies) or END
    builder.add_conditional_edges(
        "detect",
        _has_anomalies,
        {"diagnose": "diagnose", END: END},
    )

    builder.add_edge("diagnose", "plan")

    # plan -> safety_router -> execute or hitl_node
    builder.add_conditional_edges(
        "plan",
        safety_router,
        {"execute": "execute", "hitl_node": "hitl_node"},
    )

    # execute -> verify_check -> explain or diagnose (retry)
    builder.add_conditional_edges(
        "execute",
        _verify_check,
        {"explain": "explain", "diagnose": "diagnose"},
    )

    # hitl_node -> approved: execute, rejected: explain
    builder.add_conditional_edges(
        "hitl_node",
        _hitl_decision,
        {"execute": "execute", "explain": "explain"},
    )

    # explain -> END
    builder.add_edge("explain", END)

    return builder


# ── Compile ──────────────────────────────────────────────────────────────

checkpointer = MemorySaver()
graph = _build_graph().compile(checkpointer=checkpointer)


# ── Convenience runner ───────────────────────────────────────────────────


def run_pipeline(
    *,
    incident_id: str | None = None,
    thread_id: str | None = None,
    initial_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Invoke the K8sWhisperer pipeline and return the final state.

    Parameters
    ----------
    incident_id:
        Unique identifier for this incident run.  Auto-generated if omitted.
    thread_id:
        LangGraph thread id for checkpointing / resumption.  Auto-generated
        if omitted.
    initial_state:
        Optional overrides merged into the default initial state.
    """
    if incident_id is None:
        incident_id = f"inc-{uuid.uuid4().hex[:8]}"
    if thread_id is None:
        thread_id = f"thread-{uuid.uuid4().hex[:8]}"

    state: dict[str, Any] = {
        "events": [],
        "anomalies": [],
        "diagnosis": "",
        "plan": None,
        "approved": False,
        "result": "",
        "audit_log": [],
        "current_anomaly_index": 0,
        "retry_count": 0,
        "incident_id": incident_id,
        "thread_id": thread_id,
        "stage_timings": {},
    }

    if initial_state:
        state.update(initial_state)

    config = {"configurable": {"thread_id": thread_id}}

    logger.info("Starting pipeline run: incident=%s, thread=%s", incident_id, thread_id)
    result = graph.invoke(state, config=config)
    logger.info("Pipeline run complete: incident=%s", incident_id)
    return result
