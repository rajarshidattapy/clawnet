#!/usr/bin/env python3
"""
ClawNet — AI-powered network security monitor for Windows
NetWatch core  +  OpenClaw intelligence engine
"""

import ctypes
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime
from typing import NamedTuple, Optional

try:
    import psutil
except ImportError:
    print("Missing dependency: pip install psutil rich anthropic")
    sys.exit(1)

try:
    from rich import box
    from rich.align import Align
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("Missing dependency: pip install psutil rich anthropic")
    sys.exit(1)

# OpenClaw must be importable whether invoked as a module or directly
try:
    from openclaw import OpenClaw
except ImportError:
    try:
        from core.openclaw import OpenClaw
    except ImportError:
        OpenClaw = None  # type: ignore[misc,assignment]

console = Console()

BANNER = r"""
  ██████╗██╗      █████╗ ██╗    ██╗███╗   ██╗███████╗████████╗
 ██╔════╝██║     ██╔══██╗██║    ██║████╗  ██║██╔════╝╚══██╔══╝
 ██║     ██║     ███████║██║ █╗ ██║██╔██╗ ██║█████╗     ██║
 ██║     ██║     ██╔══██║██║███╗██║██║╚██╗██║██╔══╝     ██║
 ╚██████╗███████╗██║  ██║╚███╔███╔╝██║ ╚████║███████╗   ██║
  ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝
"""

STATUS_STYLE = {
    "ESTABLISHED": "bold green",
    "LISTEN":      "bold cyan",
    "TIME_WAIT":   "yellow",
    "CLOSE_WAIT":  "bold yellow",
    "SYN_SENT":    "bold magenta",
    "SYN_RECV":    "magenta",
    "FIN_WAIT1":   "dim yellow",
    "FIN_WAIT2":   "dim yellow",
    "LAST_ACK":    "dim red",
    "CLOSING":     "dim red",
    "CLOSE":       "dim white",
    "NONE":        "dim white",
}

RISK_PORTS: dict[int, tuple[str, str]] = {
    21:    ("FTP",        "red"),
    22:    ("SSH",        "yellow"),
    23:    ("Telnet",     "bold red"),
    25:    ("SMTP",       "yellow"),
    53:    ("DNS",        "cyan"),
    80:    ("HTTP",       "white"),
    443:   ("HTTPS",      "green"),
    3306:  ("MySQL",      "bold yellow"),
    3389:  ("RDP",        "bold red"),
    5432:  ("PostgreSQL", "bold yellow"),
    8080:  ("HTTP-Alt",   "white"),
    8443:  ("HTTPS-Alt",  "green"),
    27017: ("MongoDB",    "bold yellow"),
    6379:  ("Redis",      "bold yellow"),
}

_PORT_SCORE: dict[int, int] = {
    23: 4, 21: 4,
    3389: 3,
    22: 2, 25: 2,
    3306: 2, 5432: 2,
    27017: 2, 6379: 2,
    80: 1, 8080: 1,
    443: 0, 8443: 0,
    53: 0,
}

# Windows suspicious process launch paths
_SUSPICIOUS_PATHS = (
    "\\AppData\\Local\\Temp\\",
    "\\AppData\\Roaming\\",
    "\\Temp\\",
    "\\Downloads\\",
    "\\Desktop\\",
    "C:\\Temp\\",
    "C:\\Windows\\Temp\\",
    "\\$Recycle.Bin\\",
)

_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.2", "172.3", "192.168.", "127.", "::1", "fe80",
)

# ── Windows helpers ───────────────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def get_vpn_status() -> tuple[str, str]:
    _VPN_KW = ("vpn", "tap-windows", "wireguard", "tun", "ppp",
               "cisco", "nordlynx", "mullvad", "expressvpn", "openconnect",
               "protonvpn", "surfshark")
    ifaces = list(psutil.net_if_addrs().keys())
    active = [i for i in ifaces if any(kw in i.lower() for kw in _VPN_KW)]
    if active:
        return f"● ACTIVE  ({active[0]})", "bold green"
    return "✗ NONE", "bold red"


def get_wifi_ssid() -> str:
    try:
        out = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, timeout=3,
        ).stdout
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.startswith("SSID") and "BSSID" not in stripped:
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    return parts[1].strip() or "—"
    except Exception:
        pass
    return "—"


def get_default_gateway() -> str:
    try:
        out = subprocess.run(
            ["ipconfig"], capture_output=True, text=True, timeout=3,
        ).stdout
        for line in out.splitlines():
            if "Default Gateway" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    gw = parts[1].strip()
                    if gw:
                        return gw
    except Exception:
        pass
    return "—"


def get_dns_servers() -> str:
    try:
        out = subprocess.run(
            ["ipconfig", "/all"], capture_output=True, text=True, timeout=3,
        ).stdout
        servers: list[str] = []
        for line in out.splitlines():
            stripped = line.strip()
            if "DNS Servers" in stripped:
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    dns = parts[1].strip()
                    if dns:
                        servers.append(dns)
        return "  ".join(servers[:2]) if servers else "—"
    except Exception:
        return "—"


# ── Autonomous response (requires admin) ──────────────────────────────────────

_remediation_log: list[str] = []
_actioned: set[tuple] = set()


def kill_process(pid: int) -> bool:
    try:
        subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            capture_output=True, timeout=5,
        )
        return True
    except Exception:
        return False


def block_ip(ip: str) -> bool:
    try:
        rule = f"ClawNet-Block-{ip}"
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule}", "dir=out", "action=block",
            f"remoteip={ip}", "protocol=any", "enable=yes",
        ], capture_output=True, timeout=5)
        return True
    except Exception:
        return False


def execute_action(action: str, pid: Optional[int], remote_ip: str) -> str:
    ts = datetime.now().strftime("%H:%M:%S")
    if action in ("kill_process", "kill_and_block") and pid:
        if kill_process(pid):
            _remediation_log.append(f"[{ts}] KILLED PID {pid}")
    if action in ("block_ip", "kill_and_block") and remote_ip:
        if block_ip(remote_ip):
            _remediation_log.append(f"[{ts}] BLOCKED {remote_ip}")
    if _remediation_log:
        return _remediation_log[-1]
    return "Action executed"


# ── Network helpers ───────────────────────────────────────────────────────────

def _is_external(ip: str) -> bool:
    if not ip or ip in ("0.0.0.0", "::"):
        return False
    return not any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def resolve_host(ip: str, timeout: float = 0.4) -> str:
    if not ip or ip in ("0.0.0.0", "::", "127.0.0.1", "::1"):
        return ip
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def port_label(port: int) -> str:
    if port in RISK_PORTS:
        name, _ = RISK_PORTS[port]
        return f"{port} [dim]({name})[/dim]"
    return str(port) if port else "—"


def port_style(port: int) -> str:
    if port in RISK_PORTS:
        return RISK_PORTS[port][1]
    return "white"


def calc_risk(conn, suspicious_path: bool = False) -> tuple[str, str]:
    rip    = conn.raddr.ip   if conn.raddr else ""
    rport  = conn.raddr.port if conn.raddr else 0
    laddr  = conn.laddr
    status = getattr(conn, "status", "NONE") or "NONE"

    effective_port = rport or (laddr.port if laddr else 0)
    score = _PORT_SCORE.get(effective_port, 1)

    if _is_external(rip) and status == "ESTABLISHED":
        score += 1
    if status == "LISTEN" and laddr and laddr.ip in ("0.0.0.0", "::"):
        score += 1
    if status == "SYN_SENT" and _is_external(rip):
        score += 1
    if suspicious_path:
        score += 2

    if score >= 4:
        return "● HIGH", "bold red"
    if score >= 2:
        return "◆ MED",  "bold yellow"
    return "○ LOW",  "dim green"


# ── GeoIP ──────────────────────────────────────────────────────────────────────

_geo_cache: dict[str, str] = {}
_geo_lock  = threading.Lock()


def _fetch_geo(ip: str) -> None:
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode"
        with urllib.request.urlopen(url, timeout=3) as r:
            d = json.loads(r.read())
            result = f"{d.get('countryCode','?')}  {d.get('country','?')}"
    except Exception:
        result = "?"
    with _geo_lock:
        _geo_cache[ip] = result


def get_geo(ip: str) -> str:
    if not ip or not _is_external(ip):
        return "[dim]local[/dim]"
    with _geo_lock:
        cached = _geo_cache.get(ip)
    if cached is not None:
        return cached
    with _geo_lock:
        _geo_cache[ip] = "…"
    threading.Thread(target=_fetch_geo, args=(ip,), daemon=True).start()
    return "…"


# ── Process info ───────────────────────────────────────────────────────────────

def get_proc_info(pid: Optional[int]) -> tuple[str, str, bool]:
    if pid is None:
        return "—", "", False
    try:
        p   = psutil.Process(pid)
        exe = p.exe()
        suspicious = any(s.lower() in exe.lower() for s in _SUSPICIOUS_PATHS)
        return p.name(), exe, suspicious
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return f"pid:{pid}", "", False


# ── New-connection tracking ────────────────────────────────────────────────────

_seen_conns: dict[tuple, float] = {}
_seen_lock  = threading.Lock()
_NEW_TTL    = 6.0


def _conn_key(conn) -> tuple:
    la = (conn.laddr.ip, conn.laddr.port) if conn.laddr else None
    ra = (conn.raddr.ip, conn.raddr.port) if conn.raddr else None
    return (la, ra, conn.pid)


def update_seen(connections: list) -> set:
    now  = time.time()
    keys = {_conn_key(c) for c in connections}
    with _seen_lock:
        for k in keys:
            if k not in _seen_conns:
                _seen_conns[k] = now
        for k in list(_seen_conns):
            if k not in keys:
                del _seen_conns[k]
        return {k for k, ts in _seen_conns.items() if now - ts < _NEW_TTL}


class _Conn(NamedTuple):
    fd: int
    family: int
    type: int
    laddr: object
    raddr: object
    status: str
    pid: Optional[int]


def get_connections() -> list:
    try:
        return psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        conns = []
        for proc in psutil.process_iter(["pid"]):
            try:
                for c in proc.net_connections(kind="inet"):
                    conns.append(_Conn(c.fd, c.family, c.type,
                                       c.laddr, c.raddr, c.status, proc.pid))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        return conns


# ── System info ────────────────────────────────────────────────────────────────

_pub_ip_cache: dict = {"value": "fetching...", "ts": 0.0}
_pub_ip_lock  = threading.Lock()


def _fetch_public_ip() -> None:
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=4) as r:
            ip = r.read().decode().strip()
    except Exception:
        ip = "unavailable"
    with _pub_ip_lock:
        _pub_ip_cache.update({"value": ip, "ts": time.time()})


def get_public_ip() -> str:
    now = time.time()
    with _pub_ip_lock:
        stale = now - _pub_ip_cache["ts"] > 60
    if stale:
        with _pub_ip_lock:
            _pub_ip_cache["ts"] = now
        threading.Thread(target=_fetch_public_ip, daemon=True).start()
    return _pub_ip_cache["value"]


def get_primary_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "unknown"
    finally:
        s.close()


def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n //= 1024
    return f"{n:.1f} TB"


# ── UI builders ────────────────────────────────────────────────────────────────

def build_header() -> Panel:
    now      = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    hostname = socket.gethostname()
    local_ip = get_primary_ip()
    pub_ip   = get_public_ip()
    ssid     = get_wifi_ssid()
    gateway  = get_default_gateway()
    dns      = get_dns_servers()
    nio      = psutil.net_io_counters()

    vpn_label, vpn_style = get_vpn_status()

    def field(label: str, value: str, val_style: str = "white") -> str:
        return f"[bold bright_green]{label}[/]  [{val_style}]{value}[/]"

    vpn_row = Align.center(
        f"[bold bright_green]VPN[/]  [{vpn_style}]{vpn_label}[/]"
        + ("   [dim](⚠ traffic exposed on public wifi without VPN)[/]"
           if "NONE" in vpn_label else "")
    )
    row1 = "   ".join([
        field("HOST",      hostname),
        field("LOCAL IP",  local_ip),
        field("PUBLIC IP", pub_ip),
    ])
    row2 = "   ".join([
        field("WIFI",    ssid),
        field("GATEWAY", gateway),
        field("DNS",     dns),
    ])
    row3 = "   ".join([
        field("TIME",   now),
        field("↑ SENT", fmt_bytes(nio.bytes_sent)),
        field("↓ RECV", fmt_bytes(nio.bytes_recv)),
    ])

    border = "bold red" if "NONE" in vpn_label else "bright_cyan"
    body   = "\n".join([str(vpn_row), row1, row2, row3])
    return Panel(Align.center(body), border_style=border, style="on black",
                 title="[bold bright_cyan]SYSTEM[/]")


def _ai_flag(openclaw, conn_key: tuple) -> tuple[str, str]:
    """Return (char, style) for the AI verdict cell."""
    if openclaw is None or not openclaw.available:
        return "", ""
    a = openclaw.get(conn_key)
    if a is None:
        return "", ""
    if a.pending:
        return "~", "dim"
    if a.level == "CRITICAL":
        return "C", "bold bright_red"
    if a.level == "SUSPICIOUS":
        return "S", "bold yellow"
    if a.level == "SAFE":
        return "✓", "dim green"
    return "?", "dim"


def build_table(
    connections: list,
    resolve: bool = False,
    new_keys: Optional[set] = None,
    openclaw=None,
) -> Table:
    new_keys = new_keys or set()
    table = Table(
        box=box.HEAVY_HEAD,
        border_style="bright_black",
        header_style="bold bright_cyan",
        show_lines=True,
        title=(
            f"[bold bright_cyan]ACTIVE CONNECTIONS[/]  "
            f"[dim]{datetime.now().strftime('%H:%M:%S')}[/]"
        ),
        caption=f"[dim]{len(connections)} connection(s)[/]",
    )
    table.add_column("№",      style="dim",          width=4,  justify="right")
    table.add_column("FLAGS",                         width=6,  justify="center")
    table.add_column("RISK",                          width=8)
    table.add_column("PROTO",  style="bright_white", width=6)
    table.add_column("STATUS",                        width=12)
    table.add_column("LOCAL",  style="bright_white", min_width=20)
    table.add_column("REMOTE",                        min_width=22)
    table.add_column("COUNTRY",                       min_width=14)
    table.add_column("PORT",                          width=18)
    table.add_column("PROCESS",                       min_width=16)
    table.add_column("PID",    style="dim",           width=7,  justify="right")

    for i, conn in enumerate(connections, 1):
        laddr_str = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—"
        rip       = conn.raddr.ip   if conn.raddr else ""
        rport     = conn.raddr.port if conn.raddr else None

        if resolve and rip:
            rhost = resolve_host(rip)
            remote_display = (
                f"{rhost}\n[dim]{rip}[/dim]" if rhost != rip else rip
            )
        else:
            remote_display = rip or "[dim]—[/dim]"

        status     = getattr(conn, "status", "NONE") or "NONE"
        status_txt = Text(status, style=STATUS_STYLE.get(status, "white"))
        proto      = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        pid_str    = str(conn.pid) if conn.pid else "—"
        port_txt   = (
            Text(port_label(rport), style=port_style(rport))
            if rport else Text("—", style="dim")
        )

        proc_name, _exe, suspicious = get_proc_info(conn.pid)
        proc_display = Text()
        if suspicious:
            proc_display.append("⚠ ", style="bold red")
        proc_display.append(proc_name,
                            style="bold red" if suspicious else "bright_magenta")

        country     = get_geo(rip) if rip else "[dim]—[/dim]"
        country_txt = Text.from_markup(country)

        risk_label, risk_style = calc_risk(conn, suspicious_path=suspicious)
        risk_txt = Text(risk_label, style=risk_style)

        ck      = _conn_key(conn)
        is_new  = ck in new_keys
        ai_char, ai_style = _ai_flag(openclaw, ck)

        flags = Text()
        if is_new:
            flags.append("★", style="bold yellow")
        if suspicious:
            flags.append("⚠", style="bold red")
        if ai_char:
            flags.append(ai_char, style=ai_style)

        row_style = "on grey7" if is_new else ""
        table.add_row(
            str(i), flags, risk_txt, proto, status_txt,
            laddr_str, remote_display, country_txt, port_txt,
            proc_display, pid_str,
            style=row_style,
        )

    return table


def build_stats(connections: list) -> Panel:
    status_counts: dict[str, int] = {}
    proc_counts:   dict[str, int] = {}
    risk_counts = {"HIGH": 0, "MED": 0, "LOW": 0}

    for c in connections:
        s = getattr(c, "status", "NONE") or "NONE"
        status_counts[s] = status_counts.get(s, 0) + 1
        name, _exe, suspicious = get_proc_info(c.pid)
        proc_counts[name] = proc_counts.get(name, 0) + 1
        label, _ = calc_risk(c, suspicious_path=suspicious)
        key = label.split()[-1]
        risk_counts[key] = risk_counts.get(key, 0) + 1

    status_lines = [
        f"  [{STATUS_STYLE.get(s, 'white')}]{s:<14}[/] [bold]{n:>3}[/]"
        for s, n in sorted(status_counts.items(), key=lambda x: -x[1])
    ]
    proc_lines = [
        f"  [bright_magenta]{name:<18}[/] [bold]{cnt:>3}[/]"
        for name, cnt in sorted(proc_counts.items(), key=lambda x: -x[1])[:6]
    ]
    risk_lines = [
        f"  [bold red]● HIGH          [/] [bold]{risk_counts['HIGH']:>3}[/]",
        f"  [bold yellow]◆ MED           [/] [bold]{risk_counts['MED']:>3}[/]",
        f"  [dim green]○ LOW           [/] [bold]{risk_counts['LOW']:>3}[/]",
    ]
    body = "\n".join([
        "[bold bright_cyan]RISK SUMMARY[/]", *risk_lines,
        "", "[bold bright_cyan]BY STATUS[/]", *status_lines,
        "", "[bold bright_cyan]TOP PROCESSES[/]", *proc_lines,
    ])
    return Panel(body, title="[bold bright_cyan]STATISTICS[/]",
                 border_style="bright_black", padding=(0, 1))


def build_openclaw_panel(openclaw) -> Panel:
    title = "[bold bright_red]⚡ OPENCLAW INTELLIGENCE[/]"

    if openclaw is None or not openclaw.available:
        missing_lib  = "[red]anthropic[/] not installed" if OpenClaw is None else ""
        missing_key  = "" if (os.environ.get("ANTHROPIC_API_KEY")) else "[yellow]ANTHROPIC_API_KEY[/] not set"
        reason = missing_lib or missing_key or "unavailable"
        body = (
            f"[dim]AI analysis disabled — {reason}.[/]\n"
            "[dim]Set ANTHROPIC_API_KEY to enable OpenClaw threat intelligence.[/]"
        )
        return Panel(body, title=title, border_style="bright_black")

    analyses = openclaw.all_analyses()
    critical   = [a for a in analyses if not a.pending and a.level == "CRITICAL"]
    suspicious = [a for a in analyses if not a.pending and a.level == "SUSPICIOUS"]
    analyzing  = sum(1 for a in analyses if a.pending)

    lines: list[str] = []
    if analyzing:
        lines.append(f"[dim]Analyzing {analyzing} connection(s)...[/dim]")

    for a in critical[:4]:
        proc = f"[bold]{a.process}[/]" if a.process else ""
        remote = f" → [dim]{a.remote}[/dim]" if a.remote else ""
        lines.append(
            f"[bold bright_red]● CRITICAL[/] {proc}{remote}  "
            f"[dim]{a.reason}[/dim]  "
            f"[red]action: {a.action}[/red]"
        )

    for a in suspicious[:3]:
        proc = f"[bold]{a.process}[/]" if a.process else ""
        remote = f" → [dim]{a.remote}[/dim]" if a.remote else ""
        lines.append(
            f"[yellow]◆ SUSPICIOUS[/] {proc}{remote}  "
            f"[dim]{a.reason}[/dim]"
        )

    if not analyses:
        lines.append("[dim]Waiting for connections to analyze...[/dim]")
    elif not critical and not suspicious and not analyzing:
        lines.append("[dim green]✓ No threats detected by OpenClaw[/dim green]")

    if _remediation_log:
        lines.append("")
        lines.append("[bold bright_cyan]REMEDIATION LOG[/]")
        for entry in _remediation_log[-3:]:
            lines.append(f"  [bold red]{entry}[/]")

    border = "bold red" if critical else ("yellow" if suspicious else "bright_black")
    return Panel("\n".join(lines), title=title, border_style=border)


# ── OpenClaw analysis request logic ───────────────────────────────────────────

def maybe_request_analysis(
    connections: list,
    new_keys: set,
    openclaw,
) -> None:
    """Queue AI analysis for new or HIGH-risk connections."""
    if openclaw is None or not openclaw.available:
        return
    for conn in connections:
        ck = _conn_key(conn)
        proc_name, exe, suspicious = get_proc_info(conn.pid)
        risk_label, _ = calc_risk(conn, suspicious_path=suspicious)
        # Only analyze new connections or ones flagged HIGH or suspicious path
        if ck not in new_keys and risk_label != "● HIGH" and not suspicious:
            continue
        rip   = conn.raddr.ip   if conn.raddr else ""
        rport = conn.raddr.port if conn.raddr else None
        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        info  = {
            "process":   proc_name,
            "exe":       exe or "unknown",
            "proto":     proto,
            "status":    getattr(conn, "status", "NONE") or "NONE",
            "local":     f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—",
            "remote":    rip,
            "rport":     rport or "",
            "country":   _geo_cache.get(rip, "?") if rip else "local",
            "suspicious": suspicious,
            "risk":      risk_label,
            "pid":       conn.pid,
        }
        openclaw.request(ck, info)


def maybe_auto_respond(connections: list, openclaw, auto: bool) -> None:
    """If --auto is set, execute OpenClaw's recommended action for CRITICAL threats."""
    if not auto or openclaw is None or not openclaw.available:
        return
    for conn in connections:
        ck = _conn_key(conn)
        if ck in _actioned:
            continue
        a = openclaw.get(ck)
        if a and not a.pending and a.level == "CRITICAL" and a.action != "none":
            _actioned.add(ck)
            rip = conn.raddr.ip if conn.raddr else ""
            execute_action(a.action, a.pid, rip)


# ── Context string for copilot ─────────────────────────────────────────────────

def build_context_string(connections: list) -> str:
    header = (
        f"Host: {socket.gethostname()}  "
        f"Local IP: {get_primary_ip()}  "
        f"Public IP: {get_public_ip()}\n"
        f"VPN: {get_vpn_status()[0]}\n\n"
        "Active connections (top 30):\n"
        f"{'Process':<20} {'Status':<14} {'Remote IP':<18} {'Country':<16} {'Risk'}\n"
        + "-" * 80
    )
    rows: list[str] = []
    for conn in connections[:30]:
        proc, _exe, suspicious = get_proc_info(conn.pid)
        rip    = conn.raddr.ip if conn.raddr else ""
        status = getattr(conn, "status", "NONE") or "NONE"
        risk, _ = calc_risk(conn, suspicious_path=suspicious)
        country = _geo_cache.get(rip, "?") if rip else "local"
        rows.append(f"{proc:<20} {status:<14} {rip:<18} {country:<16} {risk}")
    return header + "\n" + "\n".join(rows)


# ── Modes ─────────────────────────────────────────────────────────────────────

def run_monitor(resolve: bool = False, auto: bool = False) -> None:
    """Live network monitor with OpenClaw AI intelligence overlay."""
    admin = is_admin()
    oc    = OpenClaw() if OpenClaw is not None else None

    console.print(Panel(
        Align.center(Text(BANNER, style="bold bright_cyan")),
        border_style="bright_cyan",
        subtitle="[dim]ClawNet  |  NetWatch + OpenClaw  |  Ctrl+C to stop[/]",
        padding=(0, 0),
    ))

    if not admin:
        console.print(Panel(
            "[yellow]Running without Administrator rights — some process info may be hidden.\n"
            "For full visibility: run as Administrator[/]",
            border_style="yellow",
            padding=(0, 1),
        ))
    if auto and not admin:
        console.print(Panel(
            "[red]--auto requires Administrator rights to kill processes and block IPs.[/]",
            border_style="red",
            padding=(0, 1),
        ))

    try:
        with Live(console=console, refresh_per_second=2, screen=False) as live:
            while True:
                connections = get_connections()
                new_keys    = update_seen(connections)
                maybe_request_analysis(connections, new_keys, oc)
                maybe_auto_respond(connections, oc, auto)
                live.update(Group(
                    build_header(),
                    build_table(connections, resolve=resolve,
                                new_keys=new_keys, openclaw=oc),
                    build_stats(connections),
                    build_openclaw_panel(oc),
                ))
                time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[bold bright_cyan]ClawNet terminated.[/]")


def run_copilot() -> None:
    """Interactive Security Copilot powered by OpenClaw."""
    oc = OpenClaw() if OpenClaw is not None else None

    console.print(Panel(
        Align.center(Text(BANNER, style="bold bright_cyan")),
        border_style="bright_cyan",
        subtitle="[dim]Security Copilot Mode  |  type 'exit' to quit[/]",
        padding=(0, 0),
    ))

    if oc is None or not oc.available:
        console.print(Panel(
            "[yellow]OpenClaw unavailable.[/]\n"
            "Install anthropic: [bold]pip install anthropic[/bold]\n"
            "Set your key:      [bold]set ANTHROPIC_API_KEY=sk-ant-...[/bold]",
            border_style="yellow",
        ))
        return

    console.print("[dim]Gathering network snapshot (3 seconds)...[/dim]")
    threading.Thread(target=_fetch_public_ip, daemon=True).start()
    time.sleep(3)
    connections = get_connections()
    context     = build_context_string(connections)

    console.print(Rule("[bold bright_cyan]Security Copilot[/]"))
    console.print(
        "[dim]Ask anything about your network. Examples:\n"
        '  "Why is chrome connecting to an unusual IP?"\n'
        '  "Should I block this RDP connection?"\n'
        '  "Is my system behaving normally?"[/dim]\n'
    )

    while True:
        try:
            question = Prompt.ask("[bold bright_cyan]>[/]")
        except (KeyboardInterrupt, EOFError):
            break
        if question.strip().lower() in ("exit", "quit", "q"):
            break
        if not question.strip():
            continue
        console.print("[dim]Thinking...[/dim]")
        answer = oc.copilot(question, context)
        console.print(Panel(answer, border_style="bright_cyan",
                            title="[bold]OpenClaw[/]"))

    console.print("\n[bold bright_cyan]Copilot session ended.[/]")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args = sys.argv[1:]

    if "--copilot" in args:
        run_copilot()
    else:
        threading.Thread(target=_fetch_public_ip, daemon=True).start()
        run_monitor(
            resolve="--resolve" in args,
            auto="--auto"    in args,
        )
