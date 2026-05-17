"""API routes for K8sWhisperer dashboard and war room."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from core.k8agent.src.config import settings
from core.k8agent.src.utils.audit import AUDIT_LOG_PATH

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["api"])

# ── Pydantic request / response models ──────────────────────────────────────


class ChatRequest(BaseModel):
    message: str


class ChatResponse(BaseModel):
    response: str


class ChaosRequest(BaseModel):
    count: int = 3


# ── Audit log reader ───────────────────────────────────────────────────────


def _read_audit_log() -> list[dict[str, Any]]:
    """Read and return the audit log entries, or an empty list on failure."""
    if not AUDIT_LOG_PATH.exists():
        return []
    try:
        return json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        logger.warning("Failed to read audit log at %s", AUDIT_LOG_PATH, exc_info=True)
        return []


# ── WebSocket connection manager ────────────────────────────────────────────


class _ConnectionManager:
    """Manages active WebSocket connections for real-time broadcasts."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.remove(ws)

    async def broadcast(self, data: dict[str, Any]) -> None:
        dead: list[WebSocket] = []
        for ws in self._connections:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.remove(ws)


ws_manager = _ConnectionManager()


# ── Endpoints ───────────────────────────────────────────────────────────────


@router.get("/incidents")
async def list_incidents() -> list[dict[str, Any]]:
    """Return a list of incidents derived from the audit log.

    Each unique ``incident_id`` in the audit trail is treated as one incident,
    with the latest entry's summary used as the incident summary.
    """
    entries = _read_audit_log()
    incidents: dict[str, dict[str, Any]] = {}
    for entry in entries:
        iid = entry.get("incident_id", "unknown")
        if iid not in incidents:
            incidents[iid] = {
                "incident_id": iid,
                "first_seen": entry.get("timestamp"),
                "stages": [],
                "summary": entry.get("summary", ""),
                "outcome": entry.get("outcome", ""),
                "anomaly_type": None,
                "severity": None,
                "affected_resource": None,
                "namespace": None,
                "confidence": None,
                "action": None,
                "blast_radius": None,
            }
        incidents[iid]["stages"].append(entry.get("stage"))
        incidents[iid]["summary"] = entry.get("summary", incidents[iid]["summary"])
        incidents[iid]["outcome"] = entry.get("outcome", incidents[iid]["outcome"])
        incidents[iid]["last_seen"] = entry.get("timestamp")
        # Extract anomaly and plan details from entry details
        details = entry.get("details", {})
        anomaly = details.get("anomaly", {})
        plan = details.get("plan", {})
        if anomaly.get("type"):
            incidents[iid]["anomaly_type"] = anomaly["type"]
            incidents[iid]["severity"] = anomaly.get("severity")
            incidents[iid]["affected_resource"] = anomaly.get("affected_resource")
            incidents[iid]["namespace"] = anomaly.get("namespace")
            incidents[iid]["confidence"] = anomaly.get("confidence")
        if plan.get("action"):
            incidents[iid]["action"] = plan["action"]
            incidents[iid]["blast_radius"] = plan.get("blast_radius")
            if plan.get("confidence"):
                incidents[iid]["confidence"] = plan["confidence"]

    return list(incidents.values())


@router.get("/audit-log")
async def get_audit_log() -> list[dict[str, Any]]:
    """Return the full audit trail."""
    return _read_audit_log()


@router.post("/chat", response_model=ChatResponse)
async def war_room_chat(body: ChatRequest) -> ChatResponse:
    """War room: send a message to the LLM with rich read-only cluster context.

    Gathers pods, events, deployments, node info, and recent incidents —
    all via READ-ONLY kubectl operations. The LLM has zero write access.
    """
    from core.k8agent.src.llm.client import llm_call

    sections: list[str] = []

    try:
        from core.k8agent.src.mcp_server.kubectl_tools import (
            get_pods, get_events, get_nodes, get_deployments, describe_pod,
        )

        # ── Pods with details ──────────────────────────────────────
        pods = get_pods(namespace=settings.NAMESPACE)
        if isinstance(pods, list):
            pod_lines = []
            for p in pods:
                status = p.get("phase", "?")
                restarts = p.get("restart_count", 0)
                ready = p.get("ready", False)
                reasons = []
                for cs in p.get("container_statuses", []):
                    if cs.get("reason"):
                        reasons.append(cs["reason"])
                reason_str = f" ({', '.join(reasons)})" if reasons else ""
                pod_lines.append(
                    f"  {p['name']}: {status}{reason_str} ready={ready} restarts={restarts}"
                )
            sections.append("Pods:\n" + "\n".join(pod_lines))

            # Auto-describe unhealthy pods for richer context
            for p in pods:
                if p.get("phase") != "Running" or not p.get("ready", True):
                    try:
                        desc = describe_pod(name=p["name"], namespace=settings.NAMESPACE)
                        if isinstance(desc, dict) and "error" not in desc:
                            events_str = ""
                            for ev in desc.get("events", [])[:5]:
                                events_str += f"\n    {ev.get('reason','?')}: {ev.get('message','')}"
                            conditions_str = ""
                            for c in desc.get("conditions", [])[:5]:
                                conditions_str += f"\n    {c.get('type','?')}={c.get('status','?')}: {c.get('message','')}"
                            sections.append(
                                f"Describe {p['name']}:"
                                f"\n  Phase: {desc.get('phase')}"
                                f"\n  Node: {desc.get('node_name', 'unscheduled')}"
                                f"\n  Conditions:{conditions_str or ' none'}"
                                f"\n  Events:{events_str or ' none'}"
                            )
                    except Exception:
                        pass

        # ── Recent events ──────────────────────────────────────────
        events = get_events(namespace=settings.NAMESPACE, limit=10)
        if isinstance(events, list) and events:
            ev_lines = []
            for e in events[:10]:
                ev_lines.append(
                    f"  [{e.get('type','?')}] {e.get('reason','?')}: "
                    f"{e.get('name','?')} — {e.get('message','')[:120]}"
                )
            sections.append("Recent Events:\n" + "\n".join(ev_lines))

        # ── Deployments ────────────────────────────────────────────
        deployments = get_deployments(namespace=settings.NAMESPACE)
        if isinstance(deployments, list) and deployments:
            dep_lines = []
            for d in deployments:
                dep_lines.append(
                    f"  {d.get('name','?')}: "
                    f"{d.get('ready_replicas',0)}/{d.get('replicas',0)} ready, "
                    f"updated={d.get('updated_replicas',0)}"
                )
            sections.append("Deployments:\n" + "\n".join(dep_lines))

        # ── Nodes ──────────────────────────────────────────────────
        nodes = get_nodes()
        if isinstance(nodes, list) and nodes:
            node_lines = []
            for n in nodes:
                conditions = {c.get("type"): c.get("status") for c in n.get("conditions", [])}
                node_lines.append(
                    f"  {n.get('name','?')}: Ready={conditions.get('Ready','?')} "
                    f"cpu={n.get('capacity',{}).get('cpu','?')} "
                    f"mem={n.get('capacity',{}).get('memory','?')}"
                )
            sections.append("Nodes:\n" + "\n".join(node_lines))

    except Exception:
        sections.append("(Unable to fetch cluster state)")
        logger.warning("war_room_chat: failed to gather context", exc_info=True)

    # ── Recent incidents from audit log ────────────────────────
    try:
        recent = _read_audit_log()[-10:]
        if recent:
            inc_lines = []
            for e in recent:
                inc_lines.append(
                    f"  [{e.get('stage','')}] {e.get('incident_id','')[:12]} "
                    f"— {e.get('summary','')[:100]}"
                )
            sections.append("Recent Audit Log:\n" + "\n".join(inc_lines))
    except Exception:
        pass

    cluster_context = "\n\n".join(sections) if sections else "(no data)"

    messages = [
        {
            "role": "system",
            "content": (
                "You are K8sWhisperer, an AI Kubernetes SRE assistant in a War Room. "
                "You have READ-ONLY access to the cluster. You can see pods, events, "
                "deployments, nodes, and recent incidents below.\n\n"
                "When the user asks to diagnose or fix something:\n"
                "- Use the evidence below to explain what's wrong and why\n"
                "- For fixes that need write access, explain what SHOULD be done and "
                "suggest the user inject a chaos cleanup or use the pipeline\n"
                "- Never pretend you executed a command — be honest about what you can see vs do\n"
                "- Be concise and actionable\n\n"
                f"=== CLUSTER STATE (live, read-only) ===\n{cluster_context}"
            ),
        },
        {"role": "user", "content": body.message},
    ]

    response_text = await llm_call(messages)
    return ChatResponse(response=response_text)


@router.get("/cluster-state")
async def get_cluster_state() -> dict[str, Any]:
    """Return current cluster state: pods and nodes."""
    result: dict[str, Any] = {"pods": [], "nodes": []}

    try:
        from core.k8agent.src.utils.k8s_client import get_core_v1

        core = get_core_v1()

        # Pods
        pods = core.list_namespaced_pod(namespace=settings.NAMESPACE)
        for pod in pods.items:
            containers = []
            for cs in (pod.status.container_statuses or []):
                state_str = "unknown"
                reason = None
                if cs.state.running:
                    state_str = "running"
                elif cs.state.waiting:
                    state_str = "waiting"
                    reason = cs.state.waiting.reason
                elif cs.state.terminated:
                    state_str = "terminated"
                    reason = cs.state.terminated.reason
                containers.append({
                    "name": cs.name,
                    "ready": cs.ready,
                    "restart_count": cs.restart_count,
                    "state": state_str,
                    "reason": reason,
                })

            result["pods"].append({
                "name": pod.metadata.name,
                "namespace": pod.metadata.namespace,
                "phase": pod.status.phase,
                "node": pod.spec.node_name,
                "containers": containers,
            })

        # Nodes
        nodes = core.list_node()
        for node in nodes.items:
            conditions = {
                c.type: c.status for c in (node.status.conditions or [])
            }
            result["nodes"].append({
                "name": node.metadata.name,
                "ready": conditions.get("Ready", "Unknown"),
                "cpu": node.status.allocatable.get("cpu", "N/A") if node.status.allocatable else "N/A",
                "memory": node.status.allocatable.get("memory", "N/A") if node.status.allocatable else "N/A",
            })

    except Exception:
        logger.warning("get_cluster_state: failed to fetch state", exc_info=True)

    return result


@router.post("/chaos")
async def inject_chaos(count: int = 3) -> dict[str, Any]:
    """Inject chaos scenarios into the cluster for demo purposes."""
    from core.k8agent.src.chaos.injector import inject_chaos as do_inject

    results = await do_inject(count=count)
    return {"injected": len(results), "scenarios": results}


@router.post("/chaos/inject")
async def inject_specific_chaos(scenario: str) -> dict[str, Any]:
    """Inject a specific chaos scenario by name."""
    from core.k8agent.src.chaos.injector import inject_specific

    return await inject_specific(scenario)


@router.post("/chaos/cleanup")
async def cleanup_chaos() -> dict[str, Any]:
    """Delete all demo pods and deployments."""
    from core.k8agent.src.chaos.injector import cleanup_demos

    return await cleanup_demos()


@router.get("/chaos/scenarios")
async def list_chaos_scenarios() -> list[dict[str, Any]]:
    """List all available chaos scenarios."""
    from core.k8agent.src.chaos.injector import list_scenarios

    return list_scenarios()


@router.get("/pods/{namespace}/{name}/logs")
async def get_pod_logs_api(namespace: str, name: str, tail: int = 100, previous: bool = False):
    """Return logs for a specific pod."""
    from core.k8agent.src.mcp_server.kubectl_tools import get_pod_logs

    result = get_pod_logs(name=name, namespace=namespace, tail_lines=tail, previous=previous)
    return result


@router.get("/traces")
async def get_traces_api(limit: int = 200):
    """Return recent LLM call traces."""
    from core.k8agent.src.tracing.tracer import get_traces

    return get_traces(limit=limit)


@router.get("/traces/{incident_id}")
async def get_incident_traces(incident_id: str):
    """Return all LLM call traces for a specific incident."""
    from core.k8agent.src.tracing.tracer import get_traces_for_incident

    return get_traces_for_incident(incident_id)


# ── Blockchain endpoints (with TTL cache) ──────────────────────────────────

import time as _time

_blockchain_cache: dict[str, Any] = {"status": None, "incidents": None}
_blockchain_cache_ts: dict[str, float] = {"status": 0.0, "incidents": 0.0}
_BLOCKCHAIN_CACHE_TTL = 30  # seconds


@router.get("/blockchain/status")
async def blockchain_status() -> dict[str, Any]:
    """Return blockchain connection status with 30s TTL cache."""
    now = _time.time()

    # Return cached response if fresh
    if _blockchain_cache["status"] and (now - _blockchain_cache_ts["status"]) < _BLOCKCHAIN_CACHE_TTL:
        return _blockchain_cache["status"]

    try:
        from core.k8agent.src.blockchain.stellar_client import get_incident_count

        if not settings.ENABLE_BLOCKCHAIN:
            result = {
                "enabled": False,
                "connection": "disabled",
                "contract_id": None,
                "network": None,
                "incident_count": 0,
            }
            _blockchain_cache["status"] = result
            _blockchain_cache_ts["status"] = now
            return result

        contract_id = settings.STELLAR_CONTRACT_ID
        has_credentials = bool(settings.STELLAR_SECRET_KEY and contract_id)

        if not has_credentials:
            result = {
                "enabled": True,
                "connection": "not_configured",
                "contract_id": None,
                "network": "testnet",
                "incident_count": 0,
            }
            _blockchain_cache["status"] = result
            _blockchain_cache_ts["status"] = now
            return result

        incident_count = await get_incident_count()

        result = {
            "enabled": True,
            "connection": "active",
            "contract_id": contract_id,
            "network": "testnet",
            "incident_count": incident_count,
        }
        _blockchain_cache["status"] = result
        _blockchain_cache_ts["status"] = now
        return result
    except Exception:
        logger.exception("Failed to fetch blockchain status")
        # Return stale cache if available
        if _blockchain_cache["status"]:
            return _blockchain_cache["status"]
        return {
            "enabled": settings.ENABLE_BLOCKCHAIN,
            "connection": "error",
            "contract_id": settings.STELLAR_CONTRACT_ID,
            "network": "testnet",
            "incident_count": 0,
        }


@router.get("/blockchain/incidents")
async def list_blockchain_incidents() -> list[dict[str, Any]]:
    """Return on-chain incident records with 30s TTL cache."""
    now = _time.time()

    # Return cached if fresh
    if _blockchain_cache["incidents"] is not None and (now - _blockchain_cache_ts["incidents"]) < _BLOCKCHAIN_CACHE_TTL:
        return _blockchain_cache["incidents"]

    if not settings.ENABLE_BLOCKCHAIN:
        return []

    entries = _read_audit_log()
    if not entries:
        return []

    # Collect unique incidents from the audit log
    seen: dict[str, dict[str, Any]] = {}
    for entry in entries:
        iid = entry.get("incident_id", "unknown")
        if iid == "unknown":
            continue

        details = entry.get("details", {})
        anomaly = details.get("anomaly", {})
        plan = details.get("plan", {})
        decision = entry.get("decision", "")

        if iid not in seen:
            seen[iid] = {
                "incident_id": iid,
                "anomaly_type": anomaly.get("type", "unknown"),
                "action": plan.get("action", "unknown"),
                "timestamp": entry.get("timestamp"),
                "confidence": float(anomaly.get("confidence") or plan.get("confidence") or 0),
                "severity": anomaly.get("severity"),
                "namespace": anomaly.get("namespace"),
                "auto_executed": decision == "auto-executed",
                "decision": decision or "unknown",
                "explorer_url": (
                    f"https://stellar.expert/explorer/testnet/contract/{settings.STELLAR_CONTRACT_ID}"
                    if settings.STELLAR_CONTRACT_ID else None
                ),
            }
        else:
            # Update with latest data
            if entry.get("timestamp"):
                seen[iid]["timestamp"] = entry["timestamp"]
            if decision:
                seen[iid]["decision"] = decision
                seen[iid]["auto_executed"] = decision == "auto-executed"

    results = list(seen.values())
    _blockchain_cache["incidents"] = results
    _blockchain_cache_ts["incidents"] = now
    return results


@router.get("/blockchain/incidents/{incident_id}")
async def get_blockchain_incident(incident_id: str) -> dict[str, Any]:
    """Return a specific on-chain incident record along with audit log metadata."""
    from core.k8agent.src.blockchain.stellar_client import get_incident_from_chain

    if not settings.ENABLE_BLOCKCHAIN:
        return {"status": "disabled", "incident_id": incident_id}

    # Gather audit log metadata for this incident
    entries = _read_audit_log()
    audit_meta: dict[str, Any] = {}
    for entry in entries:
        if entry.get("incident_id") == incident_id:
            details = entry.get("details", {})
            anomaly = details.get("anomaly", {})
            plan = details.get("plan", {})
            audit_meta = {
                "anomaly_type": anomaly.get("type"),
                "action": plan.get("action"),
                "severity": anomaly.get("severity"),
                "confidence": anomaly.get("confidence") or plan.get("confidence"),
                "namespace": anomaly.get("namespace"),
                "affected_resource": anomaly.get("affected_resource"),
                "timestamp": entry.get("timestamp"),
                "summary": entry.get("summary", ""),
                "outcome": entry.get("outcome", ""),
            }
            # Keep iterating to get latest timestamp / summary
    if not audit_meta:
        audit_meta = {"note": "No audit log entries found for this incident"}

    # Fetch the on-chain record
    try:
        chain_record = await get_incident_from_chain(incident_id)
    except Exception:
        logger.exception("Failed to fetch blockchain record for %s", incident_id)
        chain_record = {"status": "error", "reason": "unexpected failure"}

    explorer_url = None
    if chain_record.get("transaction_hash"):
        explorer_url = (
            f"https://stellar.expert/explorer/testnet/tx/{chain_record['transaction_hash']}"
        )

    return {
        "incident_id": incident_id,
        "audit_log": audit_meta,
        "blockchain": chain_record,
        "explorer_url": explorer_url,
    }


@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    """WebSocket for real-time incident update broadcasts."""
    await ws_manager.connect(ws)
    try:
        while True:
            # Keep the connection alive; clients only receive broadcasts
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
