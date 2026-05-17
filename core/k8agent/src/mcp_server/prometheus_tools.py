"""FastMCP tools for Prometheus queries, OOM prediction, and resource trend analysis.

Wraps the existing OOM predictor and provides generic PromQL access plus
namespace-level memory and CPU trend helpers.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from core.k8agent.src.config import settings
from core.k8agent.src.prediction.oom_predictor import predict_oom as _predict_oom

logger = logging.getLogger(__name__)

mcp_server = FastMCP(name="prometheus-tools")

# ── Helpers ──────────────────────────────────────────────────────────────


def _error(msg: str, exc: Exception | None = None) -> dict[str, Any]:
    """Return a standardised error dict."""
    d: dict[str, Any] = {"error": msg}
    if exc:
        d["detail"] = str(exc)
    return d


async def _prometheus_query_range(
    query: str,
    duration_minutes: int = 5,
    step_seconds: int = 15,
) -> dict[str, Any]:
    """Execute a PromQL range query against the configured Prometheus instance."""
    if not settings.PROMETHEUS_URL:
        return _error("PROMETHEUS_URL is not configured")

    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=duration_minutes)

    params = {
        "query": query,
        "start": start.isoformat(),
        "end": end.isoformat(),
        "step": f"{step_seconds}s",
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{settings.PROMETHEUS_URL}/api/v1/query_range",
                params=params,
            )
            resp.raise_for_status()
            return resp.json()
    except (httpx.HTTPError, httpx.InvalidURL) as exc:
        logger.error("Prometheus query failed: %s", exc)
        return _error("Prometheus query failed", exc)


# ── MCP Tools ────────────────────────────────────────────────────────────


@mcp_server.tool()
async def predict_oom(
    pod_name: str,
    namespace: str = "k8swhisperer-demo",
) -> dict[str, Any]:
    """Predict whether a pod will be OOM-killed soon.

    Uses linear regression on the last 5 minutes of memory data from
    Prometheus and extrapolates when the pod will hit its memory limit.
    Returns the prediction details or a message indicating no OOM risk.
    """
    try:
        prediction = await _predict_oom(pod_name, namespace)
        if prediction is not None:
            return prediction
        return {"status": "ok", "message": f"No OOM risk detected for pod {pod_name} in namespace {namespace}"}
    except Exception as exc:
        logger.exception("predict_oom failed for %s/%s", namespace, pod_name)
        return _error("Failed to predict OOM", exc)


@mcp_server.tool()
async def query_prometheus(
    query: str,
    duration_minutes: int = 5,
) -> dict[str, Any]:
    """Run an arbitrary PromQL range query against Prometheus.

    Queries the ``/api/v1/query_range`` endpoint with the provided *query*
    string over the last *duration_minutes* minutes.  Returns the raw
    Prometheus JSON response.
    """
    try:
        return await _prometheus_query_range(query, duration_minutes=duration_minutes)
    except Exception as exc:
        logger.exception("query_prometheus failed")
        return _error("Failed to execute Prometheus query", exc)


@mcp_server.tool()
async def get_memory_trends(
    namespace: str = "k8swhisperer-demo",
) -> dict[str, Any]:
    """Get memory usage trends for all pods in a namespace.

    Queries ``container_memory_working_set_bytes`` and returns pod-by-pod
    current memory usage in megabytes.
    """
    query = f'container_memory_working_set_bytes{{namespace="{namespace}"}}'
    try:
        data = await _prometheus_query_range(query, duration_minutes=5)

        if "error" in data:
            return data

        results = data.get("data", {}).get("result", [])
        if not results:
            return {
                "namespace": namespace,
                "pod_count": 0,
                "pods": [],
                "message": "No memory data found for this namespace",
            }

        bytes_per_mb = 1024 * 1024
        pods: list[dict[str, Any]] = []
        for series in results:
            metric = series.get("metric", {})
            values = series.get("values", [])
            if not values:
                continue
            current_bytes = float(values[-1][1])
            pods.append({
                "pod": metric.get("pod", "unknown"),
                "container": metric.get("container", "unknown"),
                "current_memory_mb": round(current_bytes / bytes_per_mb, 2),
                "data_points": len(values),
            })

        # Sort by memory usage descending
        pods.sort(key=lambda p: p["current_memory_mb"], reverse=True)

        return {
            "namespace": namespace,
            "pod_count": len(pods),
            "pods": pods,
        }
    except Exception as exc:
        logger.exception("get_memory_trends failed for namespace %s", namespace)
        return _error("Failed to get memory trends", exc)


@mcp_server.tool()
async def get_cpu_trends(
    namespace: str = "k8swhisperer-demo",
) -> dict[str, Any]:
    """Get CPU usage trends for all pods in a namespace.

    Queries ``rate(container_cpu_usage_seconds_total[5m])`` and returns
    pod-by-pod current CPU usage in cores.
    """
    query = f'rate(container_cpu_usage_seconds_total{{namespace="{namespace}"}}[5m])'
    try:
        data = await _prometheus_query_range(query, duration_minutes=5)

        if "error" in data:
            return data

        results = data.get("data", {}).get("result", [])
        if not results:
            return {
                "namespace": namespace,
                "pod_count": 0,
                "pods": [],
                "message": "No CPU data found for this namespace",
            }

        pods: list[dict[str, Any]] = []
        for series in results:
            metric = series.get("metric", {})
            values = series.get("values", [])
            if not values:
                continue
            current_cpu = float(values[-1][1])
            pods.append({
                "pod": metric.get("pod", "unknown"),
                "container": metric.get("container", "unknown"),
                "current_cpu_cores": round(current_cpu, 4),
                "current_cpu_millicores": round(current_cpu * 1000, 1),
                "data_points": len(values),
            })

        # Sort by CPU usage descending
        pods.sort(key=lambda p: p["current_cpu_cores"], reverse=True)

        return {
            "namespace": namespace,
            "pod_count": len(pods),
            "pods": pods,
        }
    except Exception as exc:
        logger.exception("get_cpu_trends failed for namespace %s", namespace)
        return _error("Failed to get CPU trends", exc)
