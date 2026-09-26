"""ClawForge terminal console — `python -m clawforge` / `clawnet forge`.

Banner, a live preflight of everything the harness needs, then a chat prompt
that hands each message to the ClawForge agent on TrueForge. Nothing here
crashes on a missing piece: every check says what is wrong and how to fix it.
"""
from __future__ import annotations

import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

import clawforge  # noqa: F401

from rich.align import Align
from rich.console import Group
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from clawforge import harness
from clawforge.harness import console

BANNER = r"""
 ██████╗██╗      █████╗ ██╗    ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██╔════╝██║     ██╔══██╗██║    ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
██║     ██║     ███████║██║ █╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
██║     ██║     ██╔══██║██║███╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
╚██████╗███████╗██║  ██║╚███╔███╔╝██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
 ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
"""

HELP = """\
[bold]Type a job for the agent[/bold], e.g.
  [cyan]Which processes on this machine look suspicious?[/cyan]
  [cyan]What is listening on port 445, and should it be?[/cyan]
  [cyan]Vet https://github.com/someone/tool.git in the sandbox before I install it[/cyan]

[bold]Commands[/bold]
  /watch    live connections + agent + prompt on one screen (Esc to return)
  /status   re-run the preflight checks      /tools   tools and their approval tier
  /setup    register provider, connector, agent in TrueForge
  /new      start a fresh session            /quit    exit"""


@dataclass
class Check:
    name: str
    ok: Optional[bool]          # True ok · False blocking · None warning
    detail: str
    fix: str = ""


def _http_status(url: str, method: str = "GET", timeout: float = 2.0) -> Optional[int]:
    """HTTP status code, or None if nothing is listening."""
    req = urllib.request.Request(url, method=method, data=b"{}" if method == "POST" else None,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:
        return None


def preflight() -> list[Check]:
    from clawforge.mcp_server import url as mcp_url
    harness.load_env()
    checks: list[Check] = []

    key = os.environ.get("OPENAI_API_KEY", "").strip()
    checks.append(Check("OpenAI key", bool(key),
                        f"set, model {harness.agent_model_id()}" if key else "OPENAI_API_KEY missing",
                        "" if key else "add OPENAI_API_KEY=sk-... to .env"))

    tf = harness.trueforge_url()
    tf_up = _http_status(f"{tf}/api/v1/agents?limit=1") == 200
    checks.append(Check("TrueForge", tf_up, tf if tf_up else f"not reachable at {tf}",
                        "" if tf_up else "python -m clawforge trueforge   (in another terminal)"))

    mcp_status = _http_status(mcp_url(), method="POST")
    mcp_up = mcp_status in (200, 400, 401, 405, 406)   # 401 = up, token enforced
    checks.append(Check("ClawNet MCP server", mcp_up,
                        f"{mcp_url()} (token enforced)" if mcp_status == 401 else
                        mcp_url() if mcp_up else f"not reachable at {mcp_url()}",
                        "" if mcp_up else "python -m clawforge serve   (in another terminal)"))

    if tf_up:
        try:
            c = harness.client()
            agent = next(iter(c.agents.list(agent_name=harness.AGENT_NAME)), None)
            names = {getattr(s, "name", "") for s in (c.settings.mcp_servers.list().data or [])}
            registered = agent is not None and harness.MCP_NAME in names
            checks.append(Check("Agent registered", registered,
                                f"agent '{harness.AGENT_NAME}' + connector '{harness.MCP_NAME}'" if registered
                                else "agent or connector missing in TrueForge",
                                "" if registered else "/setup"))
        except Exception as exc:
            checks.append(Check("Agent registered", False, f"could not query TrueForge: {exc}"[:120], "/setup"))
    else:
        checks.append(Check("Agent registered", False, "needs TrueForge first", "start TrueForge, then /setup"))

    try:
        from sandbox import _docker_available
        docker = _docker_available()
    except Exception:
        docker = False
    checks.append(Check("Docker sandbox", True if docker else None,
                        "daemon running" if docker else "not running — sandbox tools will report an error",
                        "" if docker else "start Docker Desktop"))
    return checks


def ready(checks: list[Check]) -> bool:
    return all(c.ok is not False for c in checks)


def status_panel(checks: list[Check]) -> Panel:
    t = Table.grid(padding=(0, 2))
    t.add_column(width=2)
    t.add_column(style="bold", min_width=20)
    t.add_column()
    t.add_column(style="yellow")
    for c in checks:
        icon = "[green]●[/green]" if c.ok else ("[yellow]◆[/yellow]" if c.ok is None else "[red]✗[/red]")
        t.add_row(icon, c.name, c.detail, c.fix)
    ok = ready(checks)
    return Panel(t, title="[bold]Harness status[/bold]",
                 subtitle="[green]ready[/green]" if ok else "[red]not ready — fix the red rows[/red]",
                 border_style="green" if ok else "red", padding=(0, 1))


def header() -> Panel:
    return Panel(
        Group(Align.center(Text(BANNER, style="bold bright_cyan")),
              Align.center(Text("Agent reasons · TrueForge orchestrates · ClawNet observes and enforces",
                                style="dim"))),
        border_style="bright_cyan", padding=(0, 0),
        subtitle="[dim]type a job · /help · /quit[/dim]",
    )


def tools_panel() -> Panel:
    import asyncio
    from clawforge.mcp_server import mcp
    t = Table(box=None, padding=(0, 2))
    t.add_column("tier", style="bold")
    t.add_column("tool", style="cyan")
    t.add_column("gate")
    colours = {"OBSERVE": "green", "EXECUTE": "blue", "CONTROL": "red"}
    gates = {"OBSERVE": "autonomous", "EXECUTE": "autonomous (Docker sandbox)",
             "CONTROL": "[bold red]human approval, every call[/bold red]"}
    for tool in asyncio.run(mcp.list_tools()):
        tr = harness.tier(tool.name)
        t.add_row(f"[{colours[tr]}]{tr}[/{colours[tr]}]", tool.name, gates[tr])
    return Panel(t, title="[bold]ClawNet tools[/bold]", border_style="bright_black")


def watch() -> None:
    """Live connections + agent output + prompt on one screen (clawforge/dashboard.py)."""
    from clawforge.dashboard import watch as run_dashboard
    run_dashboard(console)


def main() -> None:
    console.print(header())
    with console.status("[dim]checking harness…[/dim]"):
        checks = preflight()
    console.print(status_panel(checks))

    if _offer_setup(checks):
        with console.status("[dim]re-checking…[/dim]"):
            checks = preflight()
        console.print(status_panel(checks))
    console.print(Panel(HELP, border_style="bright_black", padding=(0, 1)))

    session_id: Optional[str] = None
    while True:
        try:
            msg = console.input("\n[bold bright_cyan]clawforge ›[/bold bright_cyan] ").strip()
        except (KeyboardInterrupt, EOFError):
            break
        if not msg:
            continue
        cmd = msg.lower()
        if cmd in ("/quit", "/exit", "exit", "quit", "/q"):
            break
        if cmd == "/help":
            console.print(Panel(HELP, border_style="bright_black", padding=(0, 1)))
        elif cmd == "/status":
            with console.status("[dim]checking harness…[/dim]"):
                checks = preflight()
            console.print(status_panel(checks))
        elif cmd == "/tools":
            console.print(tools_panel())
        elif cmd == "/watch":
            watch()
        elif cmd == "/setup":
            _setup()
        elif cmd == "/new":
            session_id = None
            console.print("[dim]next message starts a new session[/dim]")
        elif cmd.startswith("/"):
            console.print(f"[yellow]unknown command {msg}[/yellow] — /help")
        else:
            with console.status("[dim]checking harness…[/dim]"):
                checks = preflight()
            if not ready(checks):
                console.print(status_panel(checks))
                continue
            try:
                session_id = harness.run(msg, session_id=session_id)
            except KeyboardInterrupt:
                console.print("\n[yellow]interrupted — the turn may still be running in TrueForge[/yellow]")
            except Exception as exc:
                console.print(f"[red]run failed:[/red] {exc}")
    console.print("[bold bright_cyan]ClawForge closed.[/bold bright_cyan]")


def _offer_setup(checks: list[Check]) -> bool:
    by = {c.name: c for c in checks}
    if (by["OpenAI key"].ok and by["TrueForge"].ok and by["ClawNet MCP server"].ok
            and not by["Agent registered"].ok):
        if Confirm.ask("TrueForge is up but the ClawForge agent isn't registered. Run setup now?",
                       default=True):
            return _setup()
    return False


def _setup() -> bool:
    try:
        harness.setup()
        return True
    except SystemExit as exc:
        console.print(f"[red]{exc}[/red]")
    except Exception as exc:
        console.print(f"[red]setup failed:[/red] {exc}")
    return False
