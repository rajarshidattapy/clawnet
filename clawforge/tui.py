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
  /news     fetch live security news and store it in Supermemory · /news <query> searches it
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


def _server_is_stale() -> str:
    """Why the running MCP server has older code than what is on disk ('' if current)."""
    import json
    from clawforge.mcp_server import SERVER_STAMP, code_mtime
    try:
        stamp = json.loads(SERVER_STAMP.read_text(encoding="utf-8"))
    except Exception:
        return "started before code tracking existed"
    if code_mtime() > float(stamp.get("code_mtime", 0)) + 1:
        return "code changed since it started"
    return ""


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
    if mcp_up:
        stale = _server_is_stale()
        if stale:
            checks[-1] = Check("ClawNet MCP server", False, f"running old code ({stale})",
                               "restart it: Ctrl+C in its terminal, then python -m clawforge serve")

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
        from sandbox import sandbox_available
        sb_ok, sb_desc = sandbox_available()
    except Exception as exc:
        sb_ok, sb_desc = False, f"sandbox check failed: {exc}"
    checks.append(Check("Sandbox", True if sb_ok else None, sb_desc,
                        "" if sb_ok else "set DAYTONA_API_KEY in .env, or start Docker Desktop"))
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
    gates = {"OBSERVE": "autonomous", "EXECUTE": "autonomous (Daytona sandbox)",
             "CONTROL": "[bold red]human approval, every call[/bold red]"}
    for tool in asyncio.run(mcp.list_tools()):
        tr = harness.tier(tool.name)
        t.add_row(f"[{colours[tr]}]{tr}[/{colours[tr]}]", tool.name, gates[tr])
    return Panel(t, title="[bold]ClawNet tools[/bold]", border_style="bright_black")


def _readable(summary: str) -> str:
    """Display-only cleanup of crawled markdown (the stored document is untouched)."""
    import re
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", " ", summary or "")          # images
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)               # links -> text
    text = re.sub(r"<br\s*/?>?|\\+|[|#*`>_]+|\"\w+\"\s*:\s*|\",", " ", text)  # tables, escapes, json keys
    return re.sub(r"\s+", " ", text).strip(' "')


def _news_table(documents: list, stored_ids: Optional[set] = None) -> Table:
    t = Table(box=None, padding=(0, 1), expand=True, header_style="bold bright_cyan")
    t.add_column("SOURCE", style="cyan", no_wrap=True, max_width=28, overflow="ellipsis")
    t.add_column("PUBLISHED", no_wrap=True, width=10)
    t.add_column("CVEs", no_wrap=True, max_width=26, overflow="ellipsis")
    t.add_column("EXPLOITED", width=9)
    t.add_column("SUMMARY", ratio=1, no_wrap=True, overflow="ellipsis")
    if stored_ids is not None:
        t.add_column("STORED", width=11)
    for d in documents:
        cves = d.get("cves") or []
        row = [
            (d.get("source") or {}).get("name", "?"),
            (d.get("publication_date") or "—")[:10],
            (", ".join(cves[:2]) + (f" +{len(cves) - 2}" if len(cves) > 2 else "")) or "—",
            "[bold red]yes[/bold red]" if d.get("exploit_available") else "[dim]no[/dim]",
            _readable(d.get("summary") or ""),
        ]
        if stored_ids is not None:
            row.append("[green]supermemory[/green]" if d.get("id") in stored_ids else "[yellow]cache[/yellow]")
        t.add_row(*row)
    return t


def fetch_news() -> Panel:
    """/news: crawl the live security sources now and store each item in Supermemory."""
    harness.load_env()
    import web_search
    svc = web_search._get_service()
    report = svc.update(force=True)
    url = os.environ.get("SUPERMEMORY_API_URL", "http://localhost:6767")
    lines = [f"fetched [bold]{report['fetched']}[/bold] source(s) live"]
    if report.get("supermemory"):
        lines.append(f"[green]{report['ingested']} stored in Supermemory[/green] ({url})")
    elif svc.available:
        lines.append(f"[yellow]Supermemory not reachable at {url}: kept in the local cache only.[/yellow] "
                     "Start it: [bold]bash scripts/supermemory-local.sh[/bold], then /news again")
    else:
        lines.append("[yellow]SUPERMEMORY_API_KEY not set: kept in the local cache only[/yellow]")
    for err in report["errors"][:5]:
        lines.append(f"[red]✗[/red] {err}")
    body = Group(_news_table(report["documents"], set(report.get("stored_ids", []))),
                 Text.from_markup("\n" + "  ·  ".join(lines[:2])),
                 *[Text.from_markup(l) for l in lines[2:]])
    return Panel(body, title="[bold]Security news[/bold]  [dim]CISA · NVD · MITRE · GitHub · MSRC · "
                             "Unit 42 · Malwarebytes · Talos[/dim]", border_style="bright_cyan")


def search_news(query: str) -> Panel:
    """/news <query>: search what is already stored (Supermemory first, then the local cache)."""
    harness.load_env()
    import web_search
    docs = web_search.search_memory(query, limit=10)
    body = _news_table(docs) if docs else Text.from_markup(
        f"[dim]Nothing stored matches '{query}'. Run /news to fetch the latest first.[/dim]")
    return Panel(body, title=f"[bold]Stored news matching[/bold] '{query}'", border_style="bright_black")


def news(arg: str) -> Panel:
    return search_news(arg) if arg else fetch_news()


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
        elif cmd == "/news" or cmd.startswith("/news "):
            with console.status("[dim]fetching live security news…[/dim]" if cmd == "/news"
                                else "[dim]searching stored news…[/dim]"):
                panel = news(msg[5:].strip())
            console.print(panel)
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
