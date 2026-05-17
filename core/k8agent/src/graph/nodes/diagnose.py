"""Diagnose node — fetches targeted evidence and runs root-cause analysis."""

from __future__ import annotations

import asyncio
import json
import logging

from core.k8agent.src.config import settings
from core.k8agent.src.graph.state import ClusterState
from core.k8agent.src.knowledge.fingerprint import compute_fingerprint
from core.k8agent.src.knowledge.runbook_store import lookup_runbook
from core.k8agent.src.llm.client import llm_call_sync, set_current_trace_id
from core.k8agent.src.llm.prompts import DIAGNOSTICIAN_SYSTEM_PROMPT
from core.k8agent.src.mcp_server.kubectl_tools import (
    describe_pod,
    get_events,
    get_nodes,
    get_pod_logs,
)
from core.k8agent.src.graph.nodes.execute import _find_owning_deployment
from core.k8agent.src.utils.audit import make_entry, write_audit_entry
from core.k8agent.src.utils.log_chunker import chunk_logs

logger = logging.getLogger(__name__)


def _gather_evidence(anomaly: dict) -> str:
    """Fetch kubectl evidence specific to the anomaly type.

    Returns a formatted string of all evidence for the LLM.
    """
    atype = anomaly.get("type", "Unknown")
    resource = anomaly.get("affected_resource", "")
    # Strip kind prefix like "pod/" or "deployment/" from resource name
    if "/" in resource:
        resource = resource.split("/", 1)[-1]
    namespace = anomaly.get("namespace", "k8swhisperer-demo")
    evidence_parts: list[str] = []

    try:
        if atype == "CrashLoopBackOff":
            # Previous logs + describe + events
            prev_logs = get_pod_logs(name=resource, namespace=namespace, previous=True, tail_lines=150)
            evidence_parts.append(f"=== Previous Container Logs ===\n{chunk_logs(prev_logs)}")

            current_logs = get_pod_logs(name=resource, namespace=namespace, tail_lines=50)
            evidence_parts.append(f"=== Current Container Logs ===\n{chunk_logs(current_logs)}")

            desc = describe_pod(name=resource, namespace=namespace)
            evidence_parts.append(f"=== Pod Describe ===\n{json.dumps(desc, indent=2, default=str)}")

            evts = get_events(namespace=namespace, limit=20)
            evidence_parts.append(f"=== Recent Events ===\n{json.dumps(evts, indent=2, default=str)}")

        elif atype == "OOMKilled":
            # Resource limits + describe
            desc = describe_pod(name=resource, namespace=namespace)
            evidence_parts.append(f"=== Pod Describe (resource limits) ===\n{json.dumps(desc, indent=2, default=str)}")

            prev_logs = get_pod_logs(name=resource, namespace=namespace, previous=True, tail_lines=100)
            evidence_parts.append(f"=== Previous Container Logs ===\n{chunk_logs(prev_logs)}")

            # Check if the pod is managed by a Deployment so the planner
            # can target the Deployment for resource patching
            owning_deploy = _find_owning_deployment(resource, namespace)
            if owning_deploy:
                evidence_parts.append(
                    f"=== Owning Deployment ===\n"
                    f"Pod '{resource}' is managed by Deployment '{owning_deploy}'. "
                    f"Resource limit changes should target deployment/{owning_deploy}."
                )

        elif atype in ("Pending", "FailedScheduling"):
            # Describe (scheduling) + node capacity
            desc = describe_pod(name=resource, namespace=namespace)
            evidence_parts.append(f"=== Pod Describe ===\n{json.dumps(desc, indent=2, default=str)}")

            nodes = get_nodes()
            evidence_parts.append(f"=== Node Capacity ===\n{json.dumps(nodes, indent=2, default=str)}")

        elif atype == "ImagePullBackOff":
            # Describe (image name)
            desc = describe_pod(name=resource, namespace=namespace)
            evidence_parts.append(f"=== Pod Describe ===\n{json.dumps(desc, indent=2, default=str)}")

        elif atype == "Evicted":
            # Node conditions
            nodes = get_nodes()
            evidence_parts.append(f"=== Node Conditions ===\n{json.dumps(nodes, indent=2, default=str)}")

            desc = describe_pod(name=resource, namespace=namespace)
            evidence_parts.append(f"=== Pod Describe ===\n{json.dumps(desc, indent=2, default=str)}")

        else:
            # Generic: describe + events
            desc = describe_pod(name=resource, namespace=namespace)
            evidence_parts.append(f"=== Pod Describe ===\n{json.dumps(desc, indent=2, default=str)}")

            evts = get_events(namespace=namespace, limit=20)
            evidence_parts.append(f"=== Recent Events ===\n{json.dumps(evts, indent=2, default=str)}")

    except Exception:
        logger.exception("Failed to gather evidence for %s/%s", atype, resource)
        evidence_parts.append("[Error gathering some evidence — partial data below]")

    return "\n\n".join(evidence_parts)


def diagnose_node(state: ClusterState) -> dict:
    """Diagnose the current anomaly using targeted evidence and an LLM.

    Returns ``{"diagnosis": "<root cause string>"}``.
    """
    anomalies = state.get("anomalies", [])
    idx = state.get("current_anomaly_index", 0)

    if not anomalies or idx >= len(anomalies):
        logger.warning("diagnose_node: no anomaly at index %d", idx)
        return {"diagnosis": "No anomaly to diagnose."}

    anomaly = anomalies[idx]
    logger.info(
        "diagnose_node: analysing %s on %s",
        anomaly.get("type"),
        anomaly.get("affected_resource"),
    )

    # Check runbook cache first
    if settings.ENABLE_RUNBOOK_CACHE:
        fingerprint = compute_fingerprint(anomaly["type"], anomaly.get("raw_signal", ""), "Pod")
        cached = lookup_runbook(fingerprint)
        if cached and cached.get("success"):
            logger.info("Runbook cache HIT for %s (fingerprint=%s)", anomaly["type"], fingerprint)
            return {"diagnosis": f"[CACHED RUNBOOK] {cached['diagnosis']}", "incident_id": state.get("incident_id", "")}

    # Set trace context for LLM call
    incident_id = state.get("incident_id", "")
    if incident_id:
        set_current_trace_id(incident_id, stage="diagnose")

    evidence = _gather_evidence(anomaly)

    user_message = (
        f"Anomaly: {json.dumps(anomaly, default=str)}\n\n"
        f"Evidence:\n{evidence}"
    )

    messages = [
        {"role": "system", "content": DIAGNOSTICIAN_SYSTEM_PROMPT},
        {"role": "user", "content": user_message},
    ]

    diagnosis = llm_call_sync(messages)

    if not diagnosis:
        diagnosis = (
            f"Unable to determine root cause for {anomaly.get('type')} "
            f"on {anomaly.get('affected_resource')}. Manual investigation required."
        )

    logger.info("diagnose_node result: %s", diagnosis[:200])

    # Write audit entry for the diagnose stage
    if incident_id:
        write_audit_entry(make_entry(
            incident_id=incident_id,
            stage="diagnose",
            summary=f"Diagnosis for {anomaly.get('type')} on {anomaly.get('affected_resource')}: {diagnosis[:200]}",
            details={"anomaly": anomaly},
        ))

    return {"diagnosis": diagnosis}
