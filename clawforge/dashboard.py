"""ClawForge /watch — live connections + agent output + prompt, on one screen.

    ┌ status line: VPN · host · IPs · time · agent state ────────────────────┐
    │ ACTIVE CONNECTIONS (compact, scrollable, one line per connection)       │
    ├ AGENT (streamed output, approvals, questions; scrollable) ──────────────┤
    │ clawforge › what you are typing▋                                        │
    └──────────────────────────────────────────────────────────────────────────┘

The table keeps refreshing while the agent works. Approvals and agent questions
are answered in the prompt box (y / n, or typed text), so nothing blocks.

Keys  Enter send · ↑/↓ connections · PgUp/PgDn agent log · Tab filter · Esc leave
"""
from __future__ import annotations

import io
import socket
import threading
import time
from datetime import datetime
from typing import Optional

from rich import box
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

import clawforge  # noqa: F401
from clawforge import harness

FILTERS = ("all", "flagged", "foreign", "listening")
HINTS = ("[dim]Enter[/] send  [dim]↑/↓[/] connections  [dim]PgUp/PgDn[/] agent log  "
         "[dim]Tab[/] filter  [dim]/help[/]  [dim]Esc[/] leave")


class Dashboard:
    def __init__(self, console: Console) -> None:
        from clawforge import capabilities as cap
        self.console = console
        self.m = cap._monitor()
        self.state = self.m.ClawState()
        self.oc = self.m.ClawNet(memory=self.m._memory_ref[0]) if getattr(self.m, "ClawNet", None) else None
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.filter = 0
        self.conn_page = 0

        # Agent output: the harness prints into this recording console.
        self.buf = io.StringIO()
        self.sink = Console(file=self.buf, force_terminal=True, color_system="truecolor",
                            width=max(60, console.size.width - 4), soft_wrap=False)
        self.log_scroll = 0          # lines scrolled up from the bottom

        self.input = ""
        self.mode = "prompt"         # prompt | approve | answer
        self.pending: Optional[dict] = None
        self.busy = False
        self.session_id: Optional[str] = None
        self.hs = harness.HarnessState()
        self.hs.state = "DONE"

    # ── data ──────────────────────────────────────────────────────────────────

    def _keep(self, conn) -> bool:
        f = FILTERS[self.filter]
        if f == "flagged":
            return self.m.verdict_for(conn)[1].level != "SAFE"
        if f == "foreign":
            return bool(conn.raddr) and self.m._is_external(conn.raddr.ip)
        if f == "listening":
            return getattr(conn, "status", "") == "LISTEN" or not conn.raddr
        return True

    def _collect(self) -> None:
        threading.Thread(target=self.m._fetch_public_ip, daemon=True).start()
        while not self.stop.is_set():
            try:
                conns = self.m.get_connections()
                new_keys = self.m.update_seen(conns)
                if self.oc is not None:
                    self.m.maybe_request_analysis(conns, new_keys, self.oc)
                shown = [c for c in conns if self._keep(c)]
                shown.sort(key=lambda c: -self.m.verdict_for(c)[1].score)
                with self.state.lock:
                    self.state.connections = shown
                    self.state.new_keys = new_keys
            except Exception:
                pass
            self.stop.wait(1.0)

    # ── panels ────────────────────────────────────────────────────────────────

    def _status_line(self) -> Text:
        m = self.m
        vpn, vpn_style = m.get_vpn_status()
        agent = f"[bold yellow]{self.hs.state}[/]" if self.busy else "[green]idle[/]"
        return Text.from_markup(
            f" [bold bright_cyan]CLAWFORGE[/]  VPN [{vpn_style}]{vpn}[/]  "
            f"HOST [white]{socket.gethostname()}[/]  LOCAL [white]{m.get_primary_ip()}[/]  "
            f"PUBLIC [white]{m.get_public_ip()}[/]  [dim]{datetime.now():%H:%M:%S}[/]   agent {agent}")

    def _connections(self, rows: int) -> Panel:
        m = self.m
        with self.state.lock:
            conns = list(self.state.connections)
            new_keys = set(self.state.new_keys)
        total = len(conns)
        pages = max(1, (total + rows - 1) // rows)
        self.conn_page = min(self.conn_page, pages - 1)
        start = self.conn_page * rows
        t = Table(box=box.SIMPLE_HEAD, expand=True, padding=(0, 1), show_edge=False,
                  header_style="bold bright_cyan", border_style="bright_black")
        for name, kw in (("№", dict(justify="right", width=4, style="dim")),
                         ("FLAGS", dict(width=5, justify="center")), ("RISK", dict(width=7)),
                         ("PROTO", dict(width=5)), ("STATUS", dict(width=11)),
                         ("LOCAL", dict(ratio=2)), ("REMOTE", dict(ratio=2)),
                         ("COUNTRY", dict(ratio=1)), ("PORT", dict(width=13)),
                         ("PROCESS", dict(ratio=2)), ("PID", dict(width=6, justify="right", style="dim"))):
            t.add_column(name, no_wrap=True, overflow="ellipsis", **kw)
        for i, conn in enumerate(conns[start:start + rows], start + 1):
            rip = conn.raddr.ip if conn.raddr else ""
            rport = conn.raddr.port if conn.raddr else None
            status = getattr(conn, "status", "NONE") or "NONE"
            proc, _, sus = m.get_proc_info(conn.pid)
            risk, risk_style = m.calc_risk(conn, suspicious_path=sus)
            ck = m._conn_key(conn)
            flags = Text()
            if ck in new_keys:
                flags.append("★", style="bold yellow")
            if sus:
                flags.append("⚠", style="bold red")
            ai_ch, ai_st = m._ai_flag(self.oc, ck)
            if ai_ch:
                flags.append(ai_ch, style=ai_st)
            t.add_row(
                str(i), flags, Text(risk, style=risk_style),
                "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                Text(status, style=m.STATUS_STYLE.get(status, "white")),
                f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—",
                rip or Text("—", style="dim"),
                Text.from_markup(m.get_geo(rip) if rip else "[dim]—[/dim]"),
                Text.from_markup(m.port_label(rport), style=m.port_style(rport)) if rport else Text("—", style="dim"),
                Text(("⚠ " if sus else "") + proc, style="bold red" if sus else "bright_magenta"),
                str(conn.pid) if conn.pid else "—",
                style="on grey7" if ck in new_keys else "",
            )
        title = (f"[bold bright_cyan]ACTIVE CONNECTIONS[/]  [dim]{min(start + 1, total)}–"
                 f"{min(start + rows, total)} of {total} · page {self.conn_page + 1}/{pages} · "
                 f"filter [bold]{FILTERS[self.filter]}[/][/]")
        return Panel(t, title=title, title_align="left", border_style="bright_black", padding=(0, 0))

    def _log(self, height: int) -> Panel:
        lines = Text.from_ansi(self.buf.getvalue()).split("\n", allow_blank=True)
        if lines and not lines[-1].plain:
            lines = lines[:-1]
        visible = max(1, height - 2)
        self.log_scroll = max(0, min(self.log_scroll, max(0, len(lines) - visible)))
        end = len(lines) - self.log_scroll
        window = lines[max(0, end - visible):end]
        body = Text("\n").join(window) if window else Text.from_markup(
            "[dim]Ask the agent anything about what you see above, e.g. "
            "'why is PID 22004 flagged?' or 'which processes look suspicious?'[/dim]")
        sub = f"[dim]↑ {self.log_scroll} lines (PgDn)[/dim]" if self.log_scroll else ""
        return Panel(body, title="[bold]AGENT[/bold]", title_align="left", subtitle=sub,
                     border_style="bright_cyan" if self.busy else "bright_black", padding=(0, 1))

    def _prompt(self) -> Panel:
        cursor = "▋" if int(time.monotonic() * 2) % 2 == 0 else " "
        if self.mode == "approve":
            tool = (self.pending or {}).get("tool", "")
            line = Text.from_markup(f"[bold yellow]APPROVE {tool}?[/]  press [bold]y[/] to allow, "
                                    f"[bold]n[/] to deny  (briefing above)")
            border = "yellow"
        elif self.mode == "answer":
            line = Text.from_markup(f"[bold magenta]answer ›[/] {self.input}{cursor}")
            border = "magenta"
        else:
            label = "[dim]agent working… commands only[/]" if self.busy else ""
            line = Text.from_markup(f"[bold bright_cyan]clawforge ›[/] ") + Text(self.input + cursor)
            if label:
                line.append_text(Text.from_markup("   " + label))
            border = "bright_cyan"
        return Panel(Group(line, Text.from_markup(HINTS)), border_style=border, padding=(0, 1))

    def render(self) -> Layout:
        h = self.console.size.height
        rows = max(4, min(12, int(h * 0.35) - 3))
        layout = Layout()
        layout.split_column(
            Layout(self._status_line(), size=1),
            Layout(self._connections(rows), size=rows + 4),
            Layout(name="log", ratio=1),
            Layout(self._prompt(), size=4),
        )
        log_height = max(3, h - 1 - (rows + 4) - 4)
        layout["log"].update(self._log(log_height))
        return layout

    # ── agent ─────────────────────────────────────────────────────────────────

    def _decide(self, tool: str, args: dict, brief: dict) -> tuple[bool, str]:
        ev = threading.Event()
        self.pending = {"tool": tool, "event": ev, "result": (False, "denied by operator")}
        self.mode = "approve"
        self.log_scroll = 0
        ev.wait()
        result = self.pending["result"]
        self.pending, self.mode = None, "prompt"
        return result

    def _reply(self, question: str, options: list) -> str:
        ev = threading.Event()
        self.pending = {"event": ev, "result": ""}
        self.mode, self.input = "answer", ""
        self.log_scroll = 0
        ev.wait()
        result = self.pending["result"]
        self.pending, self.mode = None, "prompt"
        return result

    def _run_agent(self, task: str) -> None:
        self.busy = True
        saved = harness.console
        harness.console = self.sink
        try:
            self.session_id = harness.run(task, session_id=self.session_id, decide=self._decide,
                                          reply=self._reply, hs=self.hs)
        except Exception as exc:
            self.sink.print(f"[red]run failed:[/red] {exc}")
        finally:
            harness.console = saved
            self.busy = False

    def _command(self, text: str) -> bool:
        """Handle a slash command. Returns False to leave the dashboard."""
        cmd = text.lower().split()[0]
        if cmd in ("/quit", "/exit", "/q"):
            return False
        if cmd == "/help":
            from clawforge.tui import HELP
            self.sink.print(Panel(HELP, border_style="bright_black"))
        elif cmd == "/clear":
            self.buf.seek(0)
            self.buf.truncate()
        elif cmd == "/new":
            self.session_id = None
            self.sink.print("[dim]next message starts a new session[/dim]")
        elif cmd == "/status":
            from clawforge.tui import preflight, status_panel
            threading.Thread(target=lambda: self.sink.print(status_panel(preflight())), daemon=True).start()
        elif cmd == "/tools":
            from clawforge.tui import tools_panel
            self.sink.print(tools_panel())
        elif cmd == "/watch":
            self.sink.print("[dim]already watching[/dim]")
        else:
            self.sink.print(f"[yellow]unknown command {text}[/yellow] — /help")
        self.log_scroll = 0
        return True

    def _submit(self) -> bool:
        text, self.input = self.input.strip(), ""
        if not text:
            return True
        if self.mode == "answer" and self.pending:
            self.pending["result"] = text
            self.pending["event"].set()
            return True
        if text.startswith("/"):
            return self._command(text)
        if self.busy:
            self.sink.print("[yellow]the agent is still working on the last job[/yellow]")
            return True
        from clawforge.tui import preflight, ready, status_panel
        checks = preflight()
        if not ready(checks):
            self.sink.print(status_panel(checks))
            return True
        threading.Thread(target=self._run_agent, args=(text,), daemon=True).start()
        return True

    # ── input ─────────────────────────────────────────────────────────────────

    def _key(self, ch: bytes, ch2: Optional[bytes]) -> bool:
        """Handle one keypress. Returns False to leave."""
        if ch2 is not None:                                  # arrows / paging
            with self.state.lock:
                total = len(self.state.connections)
            if ch2 == b"H":
                self.conn_page = max(0, self.conn_page - 1)
            elif ch2 == b"P":
                self.conn_page = self.conn_page + 1 if total else 0
            elif ch2 == b"I":
                self.log_scroll += 5
            elif ch2 == b"Q":
                self.log_scroll = max(0, self.log_scroll - 5)
            return True
        if self.mode == "approve":
            if ch in (b"y", b"Y", b"n", b"N") and self.pending:
                ok = ch in (b"y", b"Y")
                self.pending["result"] = (ok, "" if ok else "denied by operator")
                self.pending["event"].set()
            return True
        if ch == b"\x1b":                                    # Esc
            if self.input:
                self.input = ""
                return True
            if self.busy:
                self.sink.print("[yellow]the agent is working — wait for it to finish before leaving[/yellow]")
                return True
            return False
        if ch == b"\t":
            self.filter = (self.filter + 1) % len(FILTERS)
            self.conn_page = 0
            return True
        if ch == b"\r":
            return self._submit()
        if ch == b"\x08":
            self.input = self.input[:-1]
            return True
        if ch == b"\x03":
            raise KeyboardInterrupt
        try:
            c = ch.decode("utf-8")
        except UnicodeDecodeError:
            return True
        if c.isprintable():
            self.input += c
        return True

    def run(self) -> None:
        try:
            import msvcrt
        except ImportError:
            self.console.print("[yellow]/watch needs a Windows console (msvcrt).[/yellow]")
            return
        threading.Thread(target=self._collect, daemon=True).start()
        with self.console.status("[dim]collecting connections…[/dim]"):
            for _ in range(30):
                with self.state.lock:
                    if self.state.connections:
                        break
                time.sleep(0.1)
        try:
            with Live(self.render(), console=self.console, screen=True,
                      refresh_per_second=4, redirect_stdout=False) as live:
                last = 0.0
                while True:
                    if msvcrt.kbhit():
                        ch = msvcrt.getch()
                        ch2 = msvcrt.getch() if ch in (b"\xe0", b"\x00") else None
                        if not self._key(ch, ch2):
                            break
                        live.update(self.render())
                        continue
                    now = time.monotonic()
                    if now - last > 0.25:
                        live.update(self.render())
                        last = now
                    time.sleep(0.02)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop.set()
            if self.pending:                                # never leave a turn hanging
                self.pending["event"].set()
        self.console.print("[dim]left watch view[/dim]")


def watch(console: Console) -> None:
    Dashboard(console).run()
