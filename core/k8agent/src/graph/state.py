"""LangGraph shared state definition with annotated reducers."""

from __future__ import annotations

import operator
from typing import Annotated, Optional, TypedDict

from core.k8agent.src.models import Anomaly, LogEntry, RemediationPlan


def _merge_dicts(a: dict, b: dict) -> dict:
    """Merge two dicts, with b taking precedence."""
    merged = {**a}
    merged.update(b)
    return merged


class ClusterState(TypedDict):
    """Shared state that flows through the K8sWhisperer LangGraph."""

    events: Annotated[list[dict], operator.add]
    anomalies: Annotated[list[Anomaly], operator.add]
    diagnosis: str
    plan: Optional[RemediationPlan]
    approved: bool
    result: str
    audit_log: Annotated[list[LogEntry], operator.add]
    current_anomaly_index: int
    retry_count: int
    incident_id: str
    thread_id: str
    stage_timings: Annotated[dict, _merge_dicts]
