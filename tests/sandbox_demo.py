#!/usr/bin/env python3
"""End-to-end sandbox demo: create a suspicious repo, sandbox it, decide promotion.

One command shows the whole secure-execution lifecycle:

    python tests/sandbox_demo.py

It writes a harmless-but-suspicious demo project to a temp folder that exercises
every telemetry feature (pip install, child processes, outbound HTTP, env reads,
~/.ssh access, a spawned shell, temp-file writes), then runs it through the real
ClawNet sandbox with live monitoring and the full chain of trust. The container
auto-removes (`docker run --rm`) and the temp folder is deleted on exit.

Requires Docker running. Pass --keep to leave the temp repo for inspection.
"""
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))

from rich.console import Console
from rich.panel import Panel

import sandbox

console = Console()

# A deliberately nosy program. Harmless — it only *reads* and prints — but it
# trips process-tree, install, network, env, sensitive-file and shell telemetry.
_DEMO_APP = r'''
import os, subprocess, sys, tempfile, urllib.request

print("[demo] starting suspicious-but-harmless workload")

# 1. child process + spawned shell
subprocess.run(["sh", "-c", "echo [demo] hello from a spawned shell"], check=False)

# 2. read environment variables (canary env vars are planted here)
for k in ("AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "PATH"):
    print(f"[demo] env {k}={os.environ.get(k, '')[:12]}")

# 3. read ~/.ssh (a decoy key is planted by the agent) and "exfiltrate" it by
#    printing it — this exposes the planted canary, which the agent catches.
for p in ("/root/.ssh/id_rsa", os.path.expanduser("~/.ssh/id_rsa")):
    try:
        with open(p) as f:
            body = f.read()
        print(f"[demo] stole {p}: {body}")
    except Exception as e:
        print(f"[demo] could not read {p}: {e}")

# 4. outbound HTTP request
try:
    with urllib.request.urlopen("http://example.com", timeout=5) as r:
        print(f"[demo] fetched example.com: {r.status}")
except Exception as e:
    print(f"[demo] http failed: {e}")

# 5. write a temp file
with tempfile.NamedTemporaryFile("w", suffix=".demo", delete=False) as t:
    t.write("scratch data")
    print(f"[demo] wrote temp file {t.name}")

print("[demo] done")
'''

_REQUIREMENTS = "requests\n"       # forces a real pip install inside the container
_START = "pip install -r requirements.txt >/dev/null 2>&1; python app.py"


def _make_demo_repo() -> Path:
    repo = Path(tempfile.mkdtemp(prefix="clawnet-demo-repo-"))
    (repo / "app.py").write_text(_DEMO_APP, encoding="utf-8")
    (repo / "requirements.txt").write_text(_REQUIREMENTS, encoding="utf-8")
    (repo / "start.sh").write_text(_START, encoding="utf-8")
    (repo / "README.md").write_text("# ClawNet sandbox demo target\n", encoding="utf-8")
    return repo


def main() -> int:
    keep = "--keep" in sys.argv

    if not sandbox._docker_available():
        console.print(Panel(
            "[red]Docker is not running.[/red] Start Docker Desktop and re-run:\n"
            "  [bold]python tests/sandbox_demo.py[/bold]",
            border_style="red", title="ClawNet Sandbox Demo",
        ))
        return 2

    repo = _make_demo_repo()
    console.print(Panel(
        f"Demo target written to:\n  [cyan]{repo}[/cyan]\n\n"
        "It will pip-install, spawn a shell, read env vars, probe ~/.ssh, make an\n"
        "outbound request and write a temp file - all inside the hardened sandbox.",
        border_style="cyan", title="ClawNet Sandbox Demo",
    ))

    runner = sandbox.SandboxRunner()
    try:
        result = runner.run_target(
            target_path=str(repo),
            runtime_command=_START,
            deep_scan=True,          # skip the trust cache — always run the container
            stream=True,             # live monitor
        )
        # run_target already prints the report + behavioral evidence.
        # promotion_gate runs and prints the full chain of trust, then prompts.
        approved = runner.promotion_gate(result)
        console.print(
            f"\n[bold]{'PROMOTED to host' if approved else 'NOT promoted — stays sandboxed'}[/bold]"
        )
        return 0 if result.risk_level != "DANGEROUS" else 1
    finally:
        if keep:
            console.print(f"[dim]Left demo repo at {repo} (--keep).[/dim]")
        else:
            shutil.rmtree(repo, ignore_errors=True)
            console.print("[dim]Cleaned up demo repo. Container auto-removed by Docker.[/dim]")


if __name__ == "__main__":
    raise SystemExit(main())
