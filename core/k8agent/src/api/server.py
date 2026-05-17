"""Main FastAPI application for K8sWhisperer."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.k8agent.src.api.routes import router as api_router
from core.k8agent.src.slack.webhook import router as slack_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: start background observation loop and Slack Socket Mode on startup."""
    from core.k8agent.src.main import observation_loop
    from core.k8agent.src.slack.listener import start_socket_mode

    task = asyncio.create_task(observation_loop(interval_seconds=45))
    logger.info("Observation loop background task started (45s interval)")

    async def _safe_socket_mode():
        try:
            await start_socket_mode()
        except Exception:
            logger.exception("Slack Socket Mode crashed")

    slack_task = asyncio.create_task(_safe_socket_mode())
    logger.info("Slack Socket Mode background task started")

    yield

    slack_task.cancel()
    task.cancel()
    for t, name in [(task, "Observation loop"), (slack_task, "Slack Socket Mode")]:
        try:
            await t
        except asyncio.CancelledError:
            logger.info("%s background task cancelled", name)


app = FastAPI(
    title="K8sWhisperer",
    description="AI-powered Kubernetes incident detection, diagnosis, and remediation",
    version="0.1.0",
    lifespan=lifespan,
)

# ── CORS (permissive for hackathon) ─────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ─────────────────────────────────────────────────────────────────

app.include_router(api_router)
app.include_router(slack_router)


# ── Health check ────────────────────────────────────────────────────────────


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Simple liveness probe."""
    return {"status": "ok"}
