#!/usr/bin/env python3
"""ClawNet Isolation Mode — interactive TUI for sandboxed project execution.

Activated via:  clawnet --isolation

This is a completely separate mode from the network monitoring dashboard.
It provides an interactive interface to:
  • Clone + sandbox a GitHub repo
  • Sandbox a local project path
  • View past sandbox run history
  • Stream live container output with real-time risk scoring
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

try:
    from sandbox import SandboxRunner, SandboxResult, _looks_like_git_url
except ImportError:
    from core.sandbox import SandboxRunner, SandboxResult, _looks_like_git_url

console = Console()

_BANNER = """
 ██████╗██╗      █████╗ ██╗    ██╗███╗   ██╗███████╗████████╗
██╔════╝██║     ██╔══██╗██║    ██║████╗  ██║██╔════╝╚══██╔══╝
██║     ██║     ███████║██║ █╗ ██║██╔██╗ ██║█████╗     ██║
██║     ██║     ██╔══██║██║███╗██║██║╚██╗██║██╔══╝     ██║
╚██████╗███████╗██║  ██║╚███╔███╔╝██║ ╚████║███████╗   ██║
 ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝
      ISOLATION MODE  —  Nothing runs on host before ClawNet approves.
"""

_LEVEL_COLOR = {"SAFE": "green", "SUSPICIOUS": "yellow", "DANGEROUS": "red"}


def _print_banner() -> None:
    console.print(Text(_BANNER, style="bold cyan"))
    console.print(Rule(style="cyan"))


def _verdict_panel(result: SandboxResult) -> Panel:
    color = _LEVEL_COLOR.get(result.risk_level, "white")
    lines: list[str] = [
        f"Run ID      : {result.run_id}",
        f"Target      : {result.target}",
        f"Risk Score  : {result.risk_score}",
        f"Risk Level  : [{color}]{result.risk_level}[/{color}]",
        f"Recommendation: {result.recommendation}",
    ]
    if result.ai_reason:
        lines.append(f"AI Analysis : {result.ai_reason}")
    if result.reasons:
        lines.append("Signals     :")
        for r in result.reasons[:6]:
            lines.append(f"  • {r}")
    border = color
    return Panel("\n".join(lines), title="[bold]Sandbox Verdict[/bold]", border_style=border)


def _show_run_history(runner: SandboxRunner) -> None:
    runs = runner.list_runs(limit=25)
    if not runs:
        console.print("[dim]No sandbox runs recorded yet.[/dim]")
        return

    table = Table(title="Recent Sandbox Runs", border_style="cyan", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Run ID", style="cyan", no_wrap=True)
    table.add_column("Target")
    table.add_column("Risk", justify="center")
    table.add_column("Score", justify="right")
    table.add_column("When")

    for i, run in enumerate(runs, 1):
        ts = run.get("ts", 0)
        when = time.strftime("%m-%d %H:%M", time.localtime(ts)) if ts else "?"
        level = run.get("risk_level", "?")
        color = _LEVEL_COLOR.get(level, "white")
        table.add_row(
            str(i),
            run.get("run_id", "?"),
            Path(run.get("target", "?")).name,
            f"[{color}]{level}[/{color}]",
            str(run.get("risk_score", 0)),
            when,
        )

    console.print(table)

    # Offer to inspect a specific run
    choice = Prompt.ask(
        "\nEnter run # to view full report (or press Enter to skip)",
        default="",
    )
    if not choice.strip():
        return
    try:
        idx = int(choice.strip()) - 1
        if 0 <= idx < len(runs):
            report = runner.load_report(runs[idx]["run_id"])
            if report:
                console.print_json(json.dumps(report, indent=2))
            else:
                console.print("[dim]Report data no longer available (temp dir was cleaned).[/dim]")
        else:
            console.print("[yellow]Invalid selection.[/yellow]")
    except ValueError:
        console.print("[yellow]Invalid input.[/yellow]")


def _run_sandbox_interactive(runner: SandboxRunner, target: str) -> Optional[SandboxResult]:
    """Prompt for options, then run sandbox with live streaming."""
    is_git = _looks_like_git_url(target)

    console.print(f"\n[cyan]Target:[/cyan] {target}")
    console.print(f"[cyan]Mode:[/cyan]   {'Clone from Git' if is_git else 'Local path'}")

    custom_cmd = Prompt.ask(
        "Custom run command (leave blank to auto-detect)",
        default="",
    )
    deep = Confirm.ask("Enable deep scan?", default=False)
    offline = Confirm.ask("Force offline mode (no network inside container)?", default=False)
    network_mode = "none" if offline else ""

    console.print(Rule("[cyan]Starting Isolation Sandbox[/cyan]"))
    console.print("[dim]Container will launch with live behavioral monitoring…[/dim]\n")

    try:
        if is_git:
            result = runner.clone_and_run(
                git_url=target,
                runtime_command=custom_cmd,
                deep_scan=deep,
                force_network_mode=network_mode,
                stream=True,
            )
        else:
            result = runner.run_target(
                target_path=target,
                runtime_command=custom_cmd,
                deep_scan=deep,
                force_network_mode=network_mode,
                stream=True,
            )
        return result
    except FileNotFoundError as exc:
        console.print(f"[red]Error:[/red] {exc}")
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
    except RuntimeError as exc:
        console.print(f"[red]Runtime error:[/red] {exc}")
    except KeyboardInterrupt:
        console.print("\n[yellow]Sandbox interrupted by user.[/yellow]")
    return None


def _promotion_flow(runner: SandboxRunner, result: SandboxResult) -> None:
    console.print()
    console.print(_verdict_panel(result))
    console.print()

    if result.risk_level == "DANGEROUS":
        console.print(Panel(
            "[bold red]DANGEROUS verdict — host promotion is blocked automatically.[/bold red]\n"
            "This project must NOT be run on the host system.",
            border_style="red",
        ))
        return

    if result.risk_level == "SAFE":
        console.print(Panel(
            "[bold green]SAFE verdict — project cleared for host promotion.[/bold green]",
            border_style="green",
        ))
        runner.promotion_gate(result)
        return

    # SUSPICIOUS — ask user
    console.print(Panel(
        "[bold yellow]SUSPICIOUS verdict — manual review required.[/bold yellow]\n"
        "Review the signals above before deciding.",
        border_style="yellow",
    ))
    approved = runner.promotion_gate(result)
    if approved:
        console.print("[green]Promotion approved by user.[/green]")
    else:
        console.print("[red]Promotion denied.[/red]")


def run_isolation_mode() -> None:
    """Entry point for clawnet --isolation."""
    # Load .env if present
    env_path = Path(__file__).parent.parent / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())

    runner = SandboxRunner()
    _print_banner()

    while True:
        console.print()
        console.print(Columns([
            "[1] Sandbox a GitHub repo (clone + run)",
            "[2] Sandbox a local project path",
            "[3] View sandbox run history",
            "[4] Manage policy file",
            "[Q] Quit isolation mode",
        ], equal=True, expand=True))
        console.print()

        choice = Prompt.ask("Choose an option", choices=["1", "2", "3", "4", "q", "Q"], default="q")
        choice = choice.strip().upper()

        if choice == "Q":
            console.print("[dim]Exiting isolation mode.[/dim]")
            break

        elif choice == "1":
            url = Prompt.ask("GitHub repo URL (must end in .git)")
            url = url.strip()
            if not url:
                continue
            result = _run_sandbox_interactive(runner, url)
            if result:
                _promotion_flow(runner, result)

        elif choice == "2":
            path = Prompt.ask("Local project path")
            path = path.strip().strip('"')
            if not path:
                continue
            result = _run_sandbox_interactive(runner, path)
            if result:
                _promotion_flow(runner, result)

        elif choice == "3":
            console.print(Rule("[cyan]Sandbox Run History[/cyan]"))
            _show_run_history(runner)

        elif choice == "4":
            policy_path = runner.ensure_policy_file()
            console.print(f"\nPolicy file: [cyan]{policy_path}[/cyan]")
            console.print("[dim]Edit this JSON file to change runtime limits, network mode, and deny lists.[/dim]")
            try:
                console.print_json(policy_path.read_text(encoding="utf-8"))
            except Exception:
                pass

        console.print(Rule(style="dim"))
