"""Native terminal controls for standalone ClawForge."""
from __future__ import annotations

import json
import os
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm

from clawforge import CORE_DIR

console_out = Console()


def load_env() -> None:
    """Load local configuration without overriding real environment values."""
    path = Path(CORE_DIR).parent / ".env"
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.lstrip().startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


def console() -> None:
    """Run the local, reasoning-routed ClawNet security copilot."""
    from clawforge import capabilities
    import llm

    provider = llm.routed("reasoning")
    console_out.print(f"[bold bright_cyan]ClawForge local copilot[/]  [dim]{provider.name}/{provider.model}[/]")
    console_out.print("[dim]Host-changing actions use `clawforge action ...` and require local confirmation.[/]")
    capabilities._monitor().run_copilot()


def status() -> None:
    from clawforge import capabilities
    console_out.print_json(json.dumps(capabilities.system_status()))


def settings(argv: list[str]) -> None:
    """Use the local settings dashboard without a TrueForge server."""
    from clawforge import monitor
    console_out.print(monitor.settings(" ".join(argv)))


def tools() -> None:
    from clawforge.mcp_server import CONTROL_TOOLS, EXECUTE_TOOLS
    from clawforge import mcp_server
    import asyncio

    for tool in asyncio.run(mcp_server.mcp.list_tools()):
        tier = "CONTROL" if tool.name in CONTROL_TOOLS else "EXECUTE" if tool.name in EXECUTE_TOOLS else "OBSERVE"
        print(f"{tier:<8} {tool.name}")


def action(argv: list[str]) -> int:
    """Run one local control action after displaying the exact target and reason."""
    from clawforge import capabilities

    actions = {
        "kill_process": ("PID REASON", lambda a: capabilities.kill_process(int(a[0]), " ".join(a[1:])), 2),
        "suspend_process": ("PID REASON", lambda a: capabilities.suspend_process(int(a[0]), " ".join(a[1:])), 2),
        "block_ip": ("IP REASON", lambda a: capabilities.block_ip(a[0], " ".join(a[1:])), 2),
        "quarantine_file": ("PATH REASON", lambda a: capabilities.quarantine_file(a[0], " ".join(a[1:])), 2),
        "close_port": ("PORT REASON", lambda a: capabilities.close_port(int(a[0]), " ".join(a[1:])), 2),
        "promote_sandbox_run": ("RUN_ID REASON", lambda a: capabilities.promote_sandbox_run(a[0], " ".join(a[1:])), 2),
    }
    if not argv or argv[0] not in actions:
        print("Usage: clawforge action <kill_process|suspend_process|block_ip|quarantine_file|close_port|promote_sandbox_run> TARGET REASON")
        return 2
    name, (usage, call, minimum) = argv[0], actions[argv[0]]
    if len(argv[1:]) < minimum:
        print(f"Usage: clawforge action {name} {usage}")
        return 2
    console_out.print(f"[bold yellow]Requested action:[/] {name}\n[bold]Target:[/] {argv[1]}\n[bold]Reason:[/] {' '.join(argv[2:])}")
    if not Confirm.ask("Apply this host-changing action?", default=False):
        console_out.print("[yellow]Denied by local operator.[/]")
        return 1
    result = call(argv[1:])
    console_out.print_json(json.dumps(result))
    return 0 if result.get("ok", result.get("promoted", False)) else 1
