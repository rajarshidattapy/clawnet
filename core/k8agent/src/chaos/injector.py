"""Chaos engineering — inject failure scenarios into the demo cluster."""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Scenario definitions ───────────────────────────────────────────────────

_MANIFESTS_DIR = Path(__file__).resolve().parents[2] / "k8s" / "demo-scenarios"


@dataclass(frozen=True)
class ChaosScenario:
    """A named chaos scenario backed by a Kubernetes manifest."""

    name: str
    yaml_path: Path


CHAOS_SCENARIOS: list[ChaosScenario] = [
    ChaosScenario(name="CrashLoopBackOff", yaml_path=_MANIFESTS_DIR / "crashloop-demo.yaml"),
    ChaosScenario(name="OOMKilled", yaml_path=_MANIFESTS_DIR / "oomkill-deploy-demo.yaml"),
    ChaosScenario(name="ImagePullBackOff", yaml_path=_MANIFESTS_DIR / "imagepull-demo.yaml"),
    ChaosScenario(name="Pending Pod", yaml_path=_MANIFESTS_DIR / "pending-demo.yaml"),
    ChaosScenario(name="Stalled Deployment", yaml_path=_MANIFESTS_DIR / "stalled-deploy.yaml"),
    ChaosScenario(name="Evicted Pod", yaml_path=_MANIFESTS_DIR / "evicted-demo.yaml"),
    ChaosScenario(name="Node Pressure", yaml_path=_MANIFESTS_DIR / "node-pressure-demo.yaml"),
]


# ── Injection logic ────────────────────────────────────────────────────────


async def _apply_manifest(scenario: ChaosScenario) -> dict[str, Any]:
    """Apply a single scenario manifest via ``kubectl apply``."""
    if not scenario.yaml_path.exists():
        msg = f"Manifest not found: {scenario.yaml_path}"
        logger.error(msg)
        return {"scenario": scenario.name, "success": False, "error": msg}

    from core.k8agent.src.config import settings

    cmd = ["kubectl", "apply", "-f", str(scenario.yaml_path)]
    if settings.KUBECONFIG:
        cmd.extend(["--kubeconfig", settings.KUBECONFIG])

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode == 0:
        logger.info("Applied scenario '%s': %s", scenario.name, stdout.decode().strip())
        return {
            "scenario": scenario.name,
            "success": True,
            "output": stdout.decode().strip(),
        }
    else:
        err = stderr.decode().strip()
        logger.error("Failed to apply scenario '%s': %s", scenario.name, err)
        return {"scenario": scenario.name, "success": False, "error": err}


async def inject_chaos(
    count: int = 3,
    stagger_seconds: int = 10,
) -> list[dict[str, Any]]:
    """Pick *count* random chaos scenarios and apply them with staggered timing.

    Parameters
    ----------
    count:
        Number of scenarios to inject (capped at the total available).
    stagger_seconds:
        Delay between successive scenario applications.

    Returns
    -------
    A list of result dicts, one per scenario applied.
    """
    available = [s for s in CHAOS_SCENARIOS if s.yaml_path.exists()]
    if not available:
        logger.warning("No chaos scenario manifests found in %s", _MANIFESTS_DIR)
        return []

    selected = random.sample(available, k=min(count, len(available)))
    results: list[dict[str, Any]] = []

    for i, scenario in enumerate(selected):
        logger.info("Injecting chaos scenario %d/%d: %s", i + 1, len(selected), scenario.name)
        result = await _apply_manifest(scenario)
        results.append(result)
        if i < len(selected) - 1:
            await asyncio.sleep(stagger_seconds)

    return results


async def inject_specific(scenario_name: str) -> dict[str, Any]:
    """Inject a specific chaos scenario by name."""
    for s in CHAOS_SCENARIOS:
        if s.name == scenario_name:
            return await _apply_manifest(s)
    return {"scenario": scenario_name, "success": False, "error": "Scenario not found"}


async def cleanup_demos() -> dict[str, Any]:
    """Delete all demo pods and deployments from the namespace."""
    from core.k8agent.src.config import settings

    kc = ["--kubeconfig", settings.KUBECONFIG] if settings.KUBECONFIG else []
    cmds = [
        ["kubectl", "delete", "pod", "--all", "-n", "k8swhisperer-demo", "--ignore-not-found"] + kc,
        ["kubectl", "delete", "deployment", "--all", "-n", "k8swhisperer-demo", "--ignore-not-found"] + kc,
    ]
    output_lines = []
    for cmd in cmds:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        out = stdout.decode().strip()
        if out:
            output_lines.append(out)
    return {"cleaned": True, "output": "\n".join(output_lines)}


def list_scenarios() -> list[dict[str, str]]:
    """Return all available chaos scenarios."""
    return [{"name": s.name, "available": s.yaml_path.exists()} for s in CHAOS_SCENARIOS]
