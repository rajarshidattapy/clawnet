"""Application configuration loaded from environment variables and .env file."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Central configuration for K8sWhisperer.

    All values can be overridden via environment variables or a .env file
    located in the project root.
    """

    # ── LiteLLM / LLM ──────────────────────────────────────────────────
    LLM_API_KEY: str = ""
    LLM_BASE_URL: str = ""
    LLM_PROVIDER: str = "litellm"
    LITELLM_MODEL_FAST: str = "claude-sonnet-4-5"
    LITELLM_MODEL_REASONING: str = "claude-sonnet-4-5"  # Use sonnet to save tokens

    # ── Slack ───────────────────────────────────────────────────────────
    SLACK_BOT_TOKEN: str = ""
    SLACK_SIGNING_SECRET: str = ""
    SLACK_CHANNEL_ID: str = ""
    SLACK_APP_TOKEN: Optional[str] = None

    # ── Kubernetes ──────────────────────────────────────────────────────
    KUBECONFIG: str = str(Path.home() / ".kube" / "config")
    NAMESPACE: str = "k8swhisperer-demo"

    # ── Stellar / Blockchain (all optional) ─────────────────────────────
    STELLAR_SECRET_KEY: Optional[str] = None
    STELLAR_CONTRACT_ID: Optional[str] = None
    STELLAR_NETWORK: str = "testnet"

    # ── Prometheus ──────────────────────────────────────────────────────
    PROMETHEUS_URL: Optional[str] = "http://localhost:9090"

    # ── Execution ──────────────────────────────────────────────────────
    DRY_RUN: bool = False

    # ── Feature flags ───────────────────────────────────────────────────
    ENABLE_PREDICTIVE_ALERTING: bool = True
    ENABLE_RUNBOOK_CACHE: bool = True
    ENABLE_MULTI_AGENT: bool = True
    ENABLE_BLOCKCHAIN: bool = True
    ENABLE_MULTI_NAMESPACE: bool = False

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }

    def model_post_init(self, __context: Any) -> None:
        # Expand ~ in KUBECONFIG path
        if self.KUBECONFIG and "~" in self.KUBECONFIG:
            object.__setattr__(self, "KUBECONFIG", str(Path(self.KUBECONFIG).expanduser()))


settings = Settings()
