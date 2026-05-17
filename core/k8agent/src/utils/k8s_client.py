"""Kubernetes API client factory.

Provides configured client instances for the kubernetes Python library,
loaded from the kubeconfig path specified in settings.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from typing import Tuple

from kubernetes import client, config
from kubernetes.client import AppsV1Api, AutoscalingV1Api, CoreV1Api

from core.k8agent.src.config import settings

logger = logging.getLogger(__name__)

_loaded = False


def _ensure_config() -> None:
    """Load kubeconfig once (idempotent).

    Tries in-cluster config first (for pod-based execution), then falls
    back to the kubeconfig file path from settings.
    """
    global _loaded
    if _loaded:
        return
    try:
        config.load_incluster_config()
        logger.info("Loaded in-cluster Kubernetes config")
    except config.ConfigException:
        try:
            config.load_kube_config(config_file=settings.KUBECONFIG)
            logger.info("Loaded kubeconfig from %s", settings.KUBECONFIG)
        except (config.ConfigException, FileNotFoundError, TypeError):
            logger.error(
                "Could not configure Kubernetes client from in-cluster "
                "config or kubeconfig (%s).",
                settings.KUBECONFIG,
            )
            raise
    _loaded = True


def get_k8s_clients() -> Tuple[CoreV1Api, AppsV1Api]:
    """Return a ``(CoreV1Api, AppsV1Api)`` tuple.

    Handles both in-cluster and external kubeconfig-based configuration.
    """
    _ensure_config()
    return client.CoreV1Api(), client.AppsV1Api()


# Convenience accessors kept for backward compatibility


def get_core_v1() -> CoreV1Api:
    """Return a CoreV1Api client."""
    _ensure_config()
    return client.CoreV1Api()


def get_apps_v1() -> AppsV1Api:
    """Return an AppsV1Api client."""
    _ensure_config()
    return client.AppsV1Api()


def get_autoscaling_v1() -> AutoscalingV1Api:
    """Return an AutoscalingV1Api client."""
    _ensure_config()
    return client.AutoscalingV1Api()
