"""K8sWhisperer entry point.

Run directly to start the FastAPI server with the background observation loop:

    python -m src.main
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid

import uvicorn

from core.k8agent.src.api.server import app  # noqa: F401 — re-exported for uvicorn

logger = logging.getLogger(__name__)

# ── Standalone observation loop ─────────────────────────────────────────────

_DEDUP_CACHE_MAX_AGE = 600  # 10 minutes


def _clear_stale_dedup_entries() -> None:
    """Remove entries older than 10 minutes from the detect node dedup cache."""
    try:
        from core.k8agent.src.graph.nodes.detect import _seen, _DEDUP_WINDOW_SECONDS

        now = time.time()
        stale_keys = [
            key for key, ts in _seen.items()
            if (now - ts) >= _DEDUP_WINDOW_SECONDS
        ]
        for key in stale_keys:
            del _seen[key]
        if stale_keys:
            logger.info("Cleared %d stale dedup cache entries", len(stale_keys))
    except Exception:
        logger.exception("Failed to clear dedup cache")


async def observation_loop(interval_seconds: int = 45) -> None:
    """Periodically invoke the LangGraph pipeline to scan the cluster.

    Designed to run as an ``asyncio.Task``.  Catches all exceptions so that
    a single failed run never kills the loop.

    Each cycle:
    1. Clears stale dedup cache entries (older than 10 minutes).
    2. Creates a fresh thread_id and invokes the full pipeline.
    3. If anomalies are found, the pipeline runs through all 7 stages.
    4. If no anomalies, just logs and waits for the next cycle.
    5. On any error, logs the traceback and continues.

    Parameters
    ----------
    interval_seconds:
        Pause between pipeline invocations (default 30 s).
    """
    from core.k8agent.src.graph.builder import run_pipeline

    logger.info(
        "observation_loop: started (interval=%ds)", interval_seconds
    )

    while True:
        thread_id = f"obs-{uuid.uuid4().hex[:8]}"
        try:
            # Housekeeping: clear stale dedup entries each cycle
            _clear_stale_dedup_entries()

            logger.info("observation_loop: starting pipeline (thread=%s)", thread_id)
            result = await asyncio.to_thread(run_pipeline, thread_id=thread_id)

            anomalies = result.get("anomalies", []) if isinstance(result, dict) else []
            if anomalies:
                logger.info(
                    "observation_loop: pipeline complete — %d anomalies processed (thread=%s)",
                    len(anomalies),
                    thread_id,
                )

                # Process remaining anomalies individually
                # Each gets its own pipeline run with the anomaly pre-set
                events = result.get("events", [])
                for idx in range(1, min(len(anomalies), 4)):  # Cap at 4 to avoid LLM cost explosion
                    extra_thread = f"obs-{uuid.uuid4().hex[:8]}"
                    extra_incident = f"inc-{uuid.uuid4().hex[:8]}"
                    try:
                        a = anomalies[idx]
                        logger.info(
                            "observation_loop: processing anomaly %d/%d: %s on %s",
                            idx + 1, len(anomalies), a.get("type"), a.get("affected_resource"),
                        )
                        # Run pipeline with pre-populated state (skips observe/detect effectively)
                        await asyncio.to_thread(
                            run_pipeline,
                            incident_id=extra_incident,
                            thread_id=extra_thread,
                            initial_state={
                                "events": events,
                                "anomalies": [a],  # Single anomaly
                                "current_anomaly_index": 0,
                            },
                        )
                    except Exception:
                        logger.exception(
                            "observation_loop: failed processing anomaly %d (thread=%s)",
                            idx + 1, extra_thread,
                        )
                    finally:
                        # Re-mark in dedup cache so it won't be double-processed next cycle
                        try:
                            from core.k8agent.src.graph.nodes.detect import _seen
                            key = (a.get("type", ""), a.get("affected_resource", ""))
                            _seen[key] = time.time()
                        except Exception:
                            pass
            else:
                logger.info("observation_loop: No anomalies detected (thread=%s)", thread_id)
        except Exception:
            logger.exception("observation_loop: pipeline run failed (thread=%s)", thread_id)
        await asyncio.sleep(interval_seconds)


# ── Main ────────────────────────────────────────────────────────────────────


def main() -> None:
    """Start the Uvicorn server on port 8000.

    The observation loop is started automatically via the FastAPI lifespan
    defined in ``src.api.server``.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )
    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
