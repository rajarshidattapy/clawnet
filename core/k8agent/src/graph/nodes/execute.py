"""Execute node — carries out the remediation plan and verifies the result."""

from __future__ import annotations

import logging
import threading
import time

from core.k8agent.src.config import settings
from core.k8agent.src.graph.state import ClusterState
from core.k8agent.src.utils.audit import make_entry, write_audit_entry
from core.k8agent.src.mcp_server.kubectl_tools import (
    delete_pod,
    get_pods,
    patch_deployment_resources,
    rollback_deployment,
)
from core.k8agent.src.utils.k8s_client import get_apps_v1, get_core_v1

logger = logging.getLogger(__name__)

_execution_locks: dict[str, threading.Lock] = {}
_locks_lock = threading.Lock()

# Backoff schedule for verification (seconds)
_VERIFY_BACKOFFS = [5, 10, 20, 40, 60]


def _find_owning_deployment(pod_name: str, namespace: str) -> str | None:
    """Find the Deployment that owns a given pod via ownerReferences.

    Walks the chain: Pod -> ReplicaSet -> Deployment.
    Returns the Deployment name, or None if the pod is not Deployment-managed.

    If the pod no longer exists (e.g. OOMKilled pods get replaced), falls back
    to matching the pod name against ReplicaSet names in the namespace, since
    pod names follow the pattern ``<replicaset-name>-<random-suffix>``.
    """
    try:
        core = get_core_v1()
        apps = get_apps_v1()

        # ── Strategy 1: read the pod directly ───────────────────────────
        rs_name: str | None = None
        try:
            pod = core.read_namespaced_pod(name=pod_name, namespace=namespace)
            for ref in pod.metadata.owner_references or []:
                if ref.kind == "ReplicaSet":
                    rs_name = ref.name
                    break
        except Exception:
            # Pod is gone (OOMKilled replacement, evicted, etc.)
            logger.info(
                "Pod %s/%s not found; falling back to ReplicaSet prefix match",
                namespace, pod_name,
            )

        # ── Strategy 2: match pod name prefix against ReplicaSets ───────
        if rs_name is None:
            rs_list = apps.list_namespaced_replica_set(namespace=namespace)
            for rs in rs_list.items:
                # Pod names are <rs-name>-<5-char-hash>
                if pod_name.startswith(rs.metadata.name + "-"):
                    rs_name = rs.metadata.name
                    logger.info(
                        "Matched pod %s to ReplicaSet %s via name prefix",
                        pod_name, rs_name,
                    )
                    break

        if rs_name is not None:
            # Find the Deployment that owns the ReplicaSet
            rs = apps.read_namespaced_replica_set(name=rs_name, namespace=namespace)
            for ref in rs.metadata.owner_references or []:
                if ref.kind == "Deployment":
                    return ref.name

        # ── Strategy 3: match pod name against Deployment names directly ──
        # Pod names follow <deployment>-<rs-hash>-<pod-hash> pattern
        dep_list = apps.list_namespaced_deployment(namespace=namespace)
        for dep in dep_list.items:
            dep_name = dep.metadata.name
            if pod_name.startswith(dep_name + "-"):
                logger.info(
                    "Matched pod %s to Deployment %s via deployment name prefix",
                    pod_name, dep_name,
                )
                return dep_name

        return None
    except Exception:
        logger.exception(
            "Failed to find owning deployment for pod %s/%s", namespace, pod_name
        )
        return None


def _execute_action(plan: dict) -> dict:
    """Map a plan action to the corresponding kubectl tool call."""
    action = plan.get("action", "")
    target = plan.get("target", "")
    # Strip kind prefix like "pod/" or "deployment/" from target name
    if "/" in target:
        target = target.split("/", 1)[-1]
    namespace = plan.get("namespace", "k8swhisperer-demo")
    params = plan.get("params", {})

    if action == "delete_pod":
        # Check if this pod is owned by a Deployment — if so, scale to 0 instead
        # of deleting the pod (which just gets recreated in an infinite loop)
        owning_deploy = _find_owning_deployment(target, namespace)
        if owning_deploy:
            logger.info(
                "delete_pod: pod %s is owned by deployment %s — scaling to 0 instead of delete loop",
                target, owning_deploy,
            )
            try:
                apps = get_apps_v1()
                body = {"spec": {"replicas": 0}}
                apps.patch_namespaced_deployment(name=owning_deploy, namespace=namespace, body=body)
                return {"status": "success", "message": f"Scaled deployment {owning_deploy} to 0 replicas (was in crash loop)"}
            except Exception as e:
                logger.warning("Failed to scale deployment %s: %s, falling back to pod delete", owning_deploy, e)
        return delete_pod(name=target, namespace=namespace)

    if action == "patch_deployment_resources":
        # The target might be a pod name; we need the owning Deployment name
        deploy_name = target
        owning = _find_owning_deployment(target, namespace)
        if owning:
            logger.info(
                "patch_deployment_resources: resolved pod %s to deployment %s",
                target, owning,
            )
            deploy_name = owning

        mem = params.get("memory_limit", "")
        cpu = params.get("cpu_limit", "")
        container_name = params.get("container_name", "") or params.get("container", "")

        # If LLM returned a percentage like "+50%", calculate the actual value
        if not mem or "%" in str(mem):
            try:
                apps = get_apps_v1()
                dep = apps.read_namespaced_deployment(name=deploy_name, namespace=namespace)
                container = dep.spec.template.spec.containers[0]
                container_name = container_name or container.name
                current_limit = container.resources.limits.get("memory", "64Mi") if container.resources and container.resources.limits else "64Mi"
                # Parse like "50Mi" -> 50, multiply by 1.5
                num = int("".join(c for c in current_limit if c.isdigit()) or "64")
                unit = "".join(c for c in current_limit if not c.isdigit()) or "Mi"
                mem = f"{int(num * 1.5)}{unit}"
                logger.info("Resolved memory +50%%: %s -> %s", current_limit, mem)
            except Exception as e:
                logger.warning("Failed to read current memory limit: %s, using 128Mi", e)
                mem = "128Mi"

        if not cpu or "%" in str(cpu):
            cpu = ""  # Don't patch CPU if not specified with actual value

        return patch_deployment_resources(
            name=deploy_name,
            namespace=namespace,
            container_name=container_name,
            memory_limit=mem,
            cpu_limit=cpu,
        )

    if action == "rollback_deployment":
        # Also resolve pod -> deployment if needed
        deploy_name = target
        owning = _find_owning_deployment(target, namespace)
        if owning:
            deploy_name = owning
        return rollback_deployment(name=deploy_name, namespace=namespace)

    if action == "no_op":
        return {"status": "no_op", "message": "No action taken per plan."}

    return {"error": f"Unknown action: {action}"}


def _verify_pod_health(pod_name: str, namespace: str) -> str:
    """Check if the target pod is Running and Ready.

    Returns a status string: "success: ..." or "failure: ...".
    """
    pods = get_pods(namespace=namespace)
    if isinstance(pods, list) and pods and "error" in pods[0]:
        return f"failure: unable to list pods — {pods[0].get('error', '')}"

    for pod in pods:
        if pod.get("name") == pod_name:
            phase = pod.get("phase", "")
            ready = pod.get("ready", False)
            if phase == "Running" and ready:
                return f"success: pod {pod_name} is Running and Ready"
            # Report the actual state for diagnosis
            statuses = pod.get("container_statuses", [])
            reasons = [
                cs.get("reason", "") for cs in statuses if cs.get("reason")
            ]
            reason_str = ", ".join(reasons) if reasons else phase
            return f"failure: pod {pod_name} is {reason_str}"

    # Pod not found — if we just deleted it, this is success
    return f"success: pod {pod_name} was removed (not found in namespace)"


def execute_node(state: ClusterState) -> dict:
    """Execute the remediation plan and verify the outcome.

    Returns ``{"result": "success: ..." or "failure: ...", "retry_count": N}``.
    """
    plan = state.get("plan")
    retry_count = state.get("retry_count", 0)

    if plan is None:
        logger.warning("execute_node: no plan to execute")
        return {"result": "failure: no plan provided", "retry_count": retry_count}

    action = plan.get("action", "no_op")
    target = plan.get("target", "")
    # Strip kind prefix like "pod/" or "deployment/"
    if "/" in target:
        target = target.split("/", 1)[-1]
    namespace = plan.get("namespace", "k8swhisperer-demo")

    incident_id = state.get("incident_id", "")
    logger.info("execute_node: executing action=%s on %s/%s", action, namespace, target)

    # Write audit entry for the execute stage
    if incident_id:
        write_audit_entry(make_entry(
            incident_id=incident_id,
            stage="execute",
            summary=f"Executing {action} on {target} in {namespace}",
            details={"plan": plan},
        ))

    # ── Dry-run guard ────────────────────────────────────────────────
    if getattr(settings, 'DRY_RUN', False):
        logger.info("DRY RUN: would execute action=%s on %s/%s", action, namespace, target)
        return {"result": f"success: [DRY RUN] would execute {action} on {target}", "retry_count": retry_count}

    # ── Resource existence check ─────────────────────────────────────
    if action == "delete_pod":
        pods = get_pods(namespace=namespace)
        pod_names = [p.get("name") for p in pods] if isinstance(pods, list) else []
        if target not in pod_names:
            logger.warning("Pod %s not found in namespace %s", target, namespace)
            return {"result": f"failure: pod {target} not found in namespace {namespace}", "retry_count": retry_count}
    elif action == "patch_deployment_resources":
        try:
            apps = get_apps_v1()
            apps.read_namespaced_deployment(name=target, namespace=namespace)
        except Exception:
            # Target might be a pod name; _execute_action resolves it, so only
            # block if we can confirm deployment truly doesn't exist.
            owning = _find_owning_deployment(target, namespace)
            if owning is None:
                logger.warning("Deployment for %s not found in namespace %s", target, namespace)
                return {"result": f"failure: deployment for {target} not found in namespace {namespace}", "retry_count": retry_count}

    # ── Acquire per-resource lock ────────────────────────────────────
    lock_key = f"{namespace}/{target}"
    with _locks_lock:
        if lock_key not in _execution_locks:
            _execution_locks[lock_key] = threading.Lock()
        resource_lock = _execution_locks[lock_key]

    if not resource_lock.acquire(timeout=5):
        logger.warning("Could not acquire lock for %s — another remediation in progress", lock_key)
        return {"result": f"failure: concurrent remediation in progress for {target}", "retry_count": retry_count}

    try:
        # ── Execute ──────────────────────────────────────────────────────
        exec_result = _execute_action(plan)

        if "error" in exec_result:
            logger.error("Execution failed: %s", exec_result["error"])
            return {
                "result": f"failure: {exec_result['error']}",
                "retry_count": retry_count + 1,
            }

        if action == "no_op" or exec_result.get("status") == "no_op":
            msg = exec_result.get("message", "no action required")
            return {"result": f"success: {msg}", "retry_count": retry_count}

        # ── Verify with backoff ──────────────────────────────────────────
        logger.info("execute_node: entering verification loop for %s", target)
        last_status = "failure: verification not started"

        for delay in _VERIFY_BACKOFFS:
            time.sleep(delay)
            last_status = _verify_pod_health(target, namespace)
            logger.info("Verify after %ds: %s", delay, last_status)
            if last_status.startswith("success"):
                return {"result": last_status, "retry_count": retry_count}

        # All verification attempts exhausted
        logger.warning("Verification failed after all backoffs: %s", last_status)
        return {"result": last_status, "retry_count": retry_count + 1}
    finally:
        resource_lock.release()
