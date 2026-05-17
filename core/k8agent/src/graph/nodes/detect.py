"""Detect node — classifies raw events into structured anomalies via LLM."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone

from core.k8agent.src.graph.state import ClusterState
from core.k8agent.src.llm.client import llm_call_json_sync, set_current_trace_id
from core.k8agent.src.llm.prompts import CLASSIFIER_SYSTEM_PROMPT
from core.k8agent.src.models import Anomaly
from core.k8agent.src.utils.audit import make_entry, write_audit_entry

logger = logging.getLogger(__name__)

# Deduplication cache: (anomaly_type, resource) -> last_seen_epoch
_seen: dict[tuple[str, str], float] = {}
_DEDUP_WINDOW_SECONDS = 600  # 10 minutes


def _is_duplicate(anomaly_type: str, resource: str) -> bool:
    """Return True if this (type, resource) pair was seen in the last 10 min."""
    key = (anomaly_type, resource)
    now = time.time()
    if key in _seen and (now - _seen[key]) < _DEDUP_WINDOW_SECONDS:
        return True
    _seen[key] = now
    return False


def _validate_anomaly(anomaly: dict, events: list[dict]) -> bool:
    """Apply additional validation rules beyond LLM classification.

    Returns True if the anomaly passes validation.
    """
    atype = anomaly.get("type", "")
    resource = anomaly.get("affected_resource", "")

    if atype == "CrashLoopBackOff":
        # Check if this restart is part of a rolling update (false positive)
        anomaly_ns = anomaly.get("namespace", "")
        for ev in events:
            if (
                ev.get("kind") == "DeploymentRollout"
                and ev.get("namespace") == anomaly_ns
                and (ev.get("updated_replicas", 0) < ev.get("desired_replicas", 0))
                and ev.get("name")
                and ev["name"] in resource
            ):
                logger.info(
                    "Skipping CrashLoopBackOff for %s: likely part of rolling "
                    "update for deployment %s (updated=%d < desired=%d)",
                    resource,
                    ev["name"],
                    ev.get("updated_replicas", 0),
                    ev.get("desired_replicas", 0),
                )
                return False

        # Verify restartCount > 3 AND not actually an OOMKill
        for ev in events:
            if ev.get("kind") == "Pod" and ev.get("name") == resource:
                # Check if any container was OOMKilled — that's a different anomaly
                for cs in ev.get("container_statuses", []):
                    if cs.get("reason") == "OOMKilled":
                        logger.info(
                            "Reclassifying CrashLoopBackOff -> OOMKilled for %s (container terminated with OOMKilled)",
                            resource,
                        )
                        anomaly["type"] = "OOMKilled"
                        return True

                total_restarts = sum(
                    cs.get("restart_count", 0)
                    for cs in ev.get("container_statuses", [])
                )
                if total_restarts <= 3:
                    logger.info(
                        "Skipping CrashLoopBackOff for %s: restartCount=%d <= 3",
                        resource, total_restarts,
                    )
                    return False
                return True
        # If we can't find the pod in events, let the anomaly through
        return True

    if atype == "CPUThrottling":
        # Verify from HPA or pod resource data that CPU is near limits
        for ev in events:
            if ev.get("kind") == "HPA" and ev.get("name") == resource:
                current_cpu = ev.get("current_cpu_utilization_percentage")
                target_cpu = ev.get("target_cpu_utilization_percentage")
                if current_cpu is not None and target_cpu is not None:
                    if current_cpu < target_cpu * 0.8:
                        logger.info(
                            "Skipping CPUThrottling for %s: CPU utilization %d%% "
                            "well below target %d%%",
                            resource, current_cpu, target_cpu,
                        )
                        return False
                return True
            # Also accept pod-level CPU evidence
            if ev.get("kind") == "Pod" and ev.get("name") == resource:
                return True
        return True

    if atype == "Pending":
        # Verify pod has been Pending for > 5 minutes
        for ev in events:
            if ev.get("kind") == "Pod" and ev.get("name") == resource:
                ts_str = ev.get("timestamp")
                if ts_str:
                    try:
                        created = datetime.fromisoformat(ts_str)
                        if created.tzinfo is None:
                            created = created.replace(tzinfo=timezone.utc)
                        age = (datetime.now(timezone.utc) - created).total_seconds()
                        if age < 300:  # less than 5 minutes
                            logger.info(
                                "Skipping Pending for %s: age=%.0fs < 300s",
                                resource, age,
                            )
                            return False
                    except (ValueError, TypeError):
                        pass
                return True
        return True

    return True


def detect_node(state: ClusterState) -> dict:
    """Classify events into anomalies using the LLM classifier.

    Returns ``{"anomalies": [...], "current_anomaly_index": 0}``.
    """
    # Skip detection if anomalies are already pre-populated (multi-anomaly processing)
    existing = state.get("anomalies", [])
    if existing:
        logger.info("detect_node: skipping — %d anomalies already populated", len(existing))
        # Return empty — state already has them, operator.add would double them
        return {"anomalies": [], "current_anomaly_index": 0}

    events = state.get("events", [])
    if not events:
        logger.info("detect_node: no events to classify")
        return {"anomalies": [], "current_anomaly_index": 0}

    # Build user prompt from events
    user_message = json.dumps(events, indent=2, default=str)

    # Set trace context for LLM call
    incident_id = state.get("incident_id", "")
    if incident_id:
        set_current_trace_id(incident_id, stage="detect")

    # Call classifier LLM
    messages = [
        {"role": "system", "content": CLASSIFIER_SYSTEM_PROMPT},
        {"role": "user", "content": user_message},
    ]

    raw_anomalies = llm_call_json_sync(messages)

    if not isinstance(raw_anomalies, list):
        logger.warning("Classifier returned non-list: %s", type(raw_anomalies))
        raw_anomalies = []

    # Validate, deduplicate, and normalise
    anomalies: list[Anomaly] = []
    for raw in raw_anomalies:
        if not isinstance(raw, dict):
            continue

        atype = raw.get("type", "Unknown")
        resource = raw.get("affected_resource", "unknown")

        if _is_duplicate(atype, resource):
            logger.info("Skipping duplicate anomaly: %s on %s", atype, resource)
            continue

        # Skip anomalies pending HITL approval (prevents duplicate Slack messages)
        try:
            from core.k8agent.src.graph.nodes.hitl import is_pending_approval
            if is_pending_approval(atype, resource):
                logger.info("Skipping anomaly pending HITL: %s on %s", atype, resource)
                continue
        except ImportError:
            pass

        if not _validate_anomaly(raw, events):
            continue

        anomaly: Anomaly = {
            "type": atype,
            "severity": raw.get("severity", "MED"),
            "affected_resource": resource,
            "namespace": raw.get("namespace", ""),
            "confidence": float(raw.get("confidence", 0.5)),
            "raw_signal": raw.get("raw_signal", ""),
            "timestamp": raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        }
        anomalies.append(anomaly)

    # All detected anomalies stay in _seen to prevent duplicates.
    # The pipeline processes index 0; remaining anomalies will be
    # naturally re-detected once the dedup window (10 min) expires,
    # which gives the first anomaly time to be remediated.

    logger.info("detect_node found %d anomalies", len(anomalies))

    # Write audit entry for the detect stage
    incident_id = state.get("incident_id", "")
    if incident_id and anomalies:
        write_audit_entry(make_entry(
            incident_id=incident_id,
            stage="detect",
            summary=f"Detected {len(anomalies)} anomalie(s): "
                    + ", ".join(f"{a['type']} on {a['affected_resource']}" for a in anomalies),
            details={"anomalies_detected": len(anomalies)},
        ))

    return {"anomalies": anomalies, "current_anomaly_index": 0}
