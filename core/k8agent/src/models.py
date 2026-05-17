"""Core data models used across K8sWhisperer."""

from __future__ import annotations

from typing import Literal, TypedDict


# ── Anomaly ─────────────────────────────────────────────────────────────

class Anomaly(TypedDict):
    """A detected cluster anomaly."""

    type: str
    severity: Literal["LOW", "MED", "HIGH", "CRITICAL"]
    affected_resource: str
    namespace: str
    confidence: float  # 0.0 – 1.0
    raw_signal: str
    timestamp: str  # ISO-8601


# ── Remediation ─────────────────────────────────────────────────────────

class RemediationPlan(TypedDict):
    """A proposed remediation action with risk metadata."""

    action: str
    target: str
    namespace: str
    params: dict
    confidence: float  # 0.0 – 1.0
    blast_radius: Literal["low", "medium", "high"]
    is_destructive: bool
    reasoning: str


# ── Audit / Logging ─────────────────────────────────────────────────────

class LogEntry(TypedDict):
    """A single entry in the incident audit trail."""

    incident_id: str
    timestamp: str  # ISO-8601
    stage: str
    summary: str
    details: dict
    decision: str
    outcome: str


# ── Constants ───────────────────────────────────────────────────────────

DESTRUCTIVE_ACTIONS: frozenset[str] = frozenset(
    {
        "rollback_deployment",
        "drain_node",
        "delete_namespace",
        "scale_down",
        "force_delete_pod",
        "cordon_node",
    }
)

ANOMALY_TYPES: dict[str, str] = {
    "CrashLoopBackOff": "restartCount > 3; Fetch logs -> diagnose -> auto restart pod",
    "OOMKilled": "lastState.terminated.reason = OOMKilled; Read limits -> patch +50% memory -> restart",
    "Pending": "pod.status.phase = Pending > 5 min; Describe -> check node capacity -> recommend",
    "ImagePullBackOff": "state.waiting.reason = ImagePullBackOff; Extract image -> alert human",
    "CPUThrottling": "Prometheus: cpu_throttled > 0.5; Patch CPU limit upward -> verify throttle drops",
    "Evicted": "pod.status.reason = Evicted; Check node pressure -> delete evicted pod",
    "DeploymentStalled": "updatedReplicas != replicas > 10 min; Check events -> HITL: rollback or force rollout",
    "NodeNotReady": "conditions[Ready] = False; Log metrics -> HITL ONLY — never auto-drain",
}
