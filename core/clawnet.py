#!/usr/bin/env python3
"""ClawNet v2 — AI-Powered Interactive Security Terminal"""

import ctypes
import hashlib
import json
import os
import queue
import re
import socket
import subprocess
import sys
import textwrap
import threading
import time
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import NamedTuple, Optional

# ── env loader ────────────────────────────────────────────────────────────────
_env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
if os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip())

if sys.platform == "win32":
    try:
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
    except Exception:
        pass

# ── imports ───────────────────────────────────────────────────────────────────
try:
    import psutil
except ImportError:
    print("pip install psutil rich openai python-telegram-bot send2trash")
    sys.exit(1)

try:
    from rich import box
    from rich.align import Align
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.live import Live
    from rich.markup import escape as _markup_escape
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("pip install rich"); sys.exit(1)

try:
    import send2trash as _send2trash
    _HAS_SEND2TRASH = True
except ImportError:
    _HAS_SEND2TRASH = False

try:
    from openclaw import OpenClaw
except ImportError:
    try:
        from core.openclaw import OpenClaw
    except ImportError:
        OpenClaw = None  # type: ignore

try:
    from telegram_alert import TelegramAlert, TelegramMock, PendingAction
except ImportError:
    try:
        from core.telegram_alert import TelegramAlert, TelegramMock, PendingAction
    except ImportError:
        TelegramAlert = None  # type: ignore
        TelegramMock  = None  # type: ignore
        PendingAction = None  # type: ignore

try:
    from memory import SuperMemory, make_event
except ImportError:
    try:
        from core.memory import SuperMemory, make_event
    except ImportError:
        SuperMemory = None  # type: ignore
        make_event  = None  # type: ignore

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
    4444:  ("ShellPort",  "bold red"),
    5432:  ("PostgreSQL", "bold yellow"),
    8080:  ("HTTP-Alt",   "white"),
    8443:  ("HTTPS-Alt",  "green"),
    27017: ("MongoDB",    "bold yellow"),
    6379:  ("Redis",      "bold yellow"),
}

_PORT_SCORE: dict[int, int] = {
    23: 4, 21: 4, 4444: 4,
    3389: 3,
    22: 2, 25: 2, 3306: 2, 5432: 2, 27017: 2, 6379: 2,
    80: 1, 8080: 1,
    443: 0, 8443: 0, 53: 0,
}

_SUSPICIOUS_PATHS = (
    "\\AppData\\Local\\Temp\\", "\\AppData\\Roaming\\",
    "\\Temp\\", "\\Downloads\\", "\\Desktop\\",
    "C:\\Temp\\", "C:\\Windows\\Temp\\", "\\$Recycle.Bin\\",
)

_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.2", "172.3", "192.168.", "127.", "::1", "fe80",
)

# ── shared state ──────────────────────────────────────────────────────────────

@dataclass
class ClawState:
    connections:   list  = field(default_factory=list)
    new_keys:      set   = field(default_factory=set)
    page:          int   = 0
    per_page:      int   = 10
    chat_mode:     bool  = False
    chat_input:    str   = ""
    chat_thinking: bool  = False
    chat_history:  deque = field(default_factory=lambda: deque(maxlen=200))
    chat_scroll:   int   = 0    # lines scrolled up from bottom (0 = latest)
    chat_queue:    queue.Queue = field(default_factory=queue.Queue)
    action_log:    deque = field(default_factory=lambda: deque(maxlen=6))
    alerted_keys:  set   = field(default_factory=set)
    actioned:      set   = field(default_factory=set)
    lock: threading.Lock = field(default_factory=threading.Lock)

# ── cursor blink ──────────────────────────────────────────────────────────────

_cur_on = True
_cur_ts = 0.0

def _blink() -> str:
    global _cur_on, _cur_ts
    now = time.monotonic()
    if now - _cur_ts > 0.5:
        _cur_on = not _cur_on
        _cur_ts = now
    return "▋" if _cur_on else " "

# ── Windows helpers ───────────────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def get_vpn_status() -> tuple[str, str]:
    _VPN_KW = ("vpn", "tap-windows", "wireguard", "tun", "ppp",
               "cisco", "nordlynx", "mullvad", "expressvpn",
               "openconnect", "protonvpn", "surfshark")
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
            s = line.strip()
            if s.startswith("SSID") and "BSSID" not in s:
                p = s.split(":", 1)
                if len(p) == 2:
                    return p[1].strip() or "—"
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
                p = line.split(":", 1)
                if len(p) == 2 and p[1].strip():
                    return p[1].strip()
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
            s = line.strip()
            if "DNS Servers" in s:
                p = s.split(":", 1)
                if len(p) == 2 and p[1].strip():
                    servers.append(p[1].strip())
        return "  ".join(servers[:2]) if servers else "—"
    except Exception:
        return "—"

# ── safe actions ──────────────────────────────────────────────────────────────

def kill_process(pid: int) -> bool:
    try:
        subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                       capture_output=True, timeout=5)
        return True
    except Exception:
        return False


def suspend_process(pid: int) -> bool:
    try:
        psutil.Process(pid).suspend()
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


def close_port(port: int) -> list[int]:
    killed: list[int] = []
    for conn in psutil.net_connections():
        if conn.laddr and conn.laddr.port == port and conn.pid:
            if kill_process(conn.pid):
                killed.append(conn.pid)
    return killed


def quarantine_file(path: str) -> bool:
    if not _HAS_SEND2TRASH:
        return False
    try:
        _send2trash.send2trash(path)
        return True
    except Exception:
        return False


def inspect_file(path: str) -> dict:
    try:
        stat = os.stat(path)
        sha256 = "?"
        try:
            with open(path, "rb") as f:
                sha256 = hashlib.sha256(f.read(2 * 1024 * 1024)).hexdigest()
        except Exception:
            pass
        return {
            "path": path, "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "sha256": sha256,
        }
    except Exception as e:
        return {"error": str(e)}


def execute_action(action_type: str, pid: Optional[int], remote_ip: str,
                   state: "ClawState") -> str:
    ts = datetime.now().strftime("%H:%M:%S")
    msg = ""
    if action_type in ("kill_process", "kill_and_block") and pid:
        ok  = kill_process(pid)
        msg = f"[{ts}] {'✓' if ok else '✗'} KILLED  pid {pid}"
        with state.lock:
            state.action_log.append(msg)
    if action_type in ("block_ip", "kill_and_block") and remote_ip:
        ok  = block_ip(remote_ip)
        msg = f"[{ts}] {'✓' if ok else '✗'} BLOCKED {remote_ip}"
        with state.lock:
            state.action_log.append(msg)
    return msg or "done"

# ── network helpers ───────────────────────────────────────────────────────────

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
    return RISK_PORTS[port][1] if port in RISK_PORTS else "white"


def calc_risk(conn, suspicious_path: bool = False) -> tuple[str, str]:
    rip    = conn.raddr.ip   if conn.raddr else ""
    rport  = conn.raddr.port if conn.raddr else 0
    laddr  = conn.laddr
    status = getattr(conn, "status", "NONE") or "NONE"
    eff    = rport or (laddr.port if laddr else 0)
    score  = _PORT_SCORE.get(eff, 1)
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

# ── GeoIP ─────────────────────────────────────────────────────────────────────

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

# ── process info ──────────────────────────────────────────────────────────────

def get_proc_info(pid: Optional[int]) -> tuple[str, str, bool]:
    if pid is None:
        return "—", "", False
    try:
        p   = psutil.Process(pid)
        exe = p.exe()
        sus = any(s.lower() in exe.lower() for s in _SUSPICIOUS_PATHS)
        return p.name(), exe, sus
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return f"pid:{pid}", "", False

# ── connection tracking ───────────────────────────────────────────────────────

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
    fd: int; family: int; type: int
    laddr: object; raddr: object; status: str; pid: Optional[int]


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

# ── system info ───────────────────────────────────────────────────────────────

_pub_ip_cache: dict = {"value": "fetching…", "ts": 0.0}
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

# ── command parser ────────────────────────────────────────────────────────────

def parse_command(text: str) -> tuple[str, dict]:
    t = text.strip()

    m = re.match(r'(?:kill\s+(?:pid\s+)?|/kill\s+)(\d+)', t, re.I)
    if m:
        return "kill", {"pid": int(m.group(1))}

    m = re.match(r'(?:block\s+(?:ip\s+)?|/block\s+)([\d.a-fA-F:]+)', t, re.I)
    if m:
        return "block", {"ip": m.group(1)}

    m = re.match(r'(?:suspend\s+(?:pid\s+)?|/suspend\s+)(\d+)', t, re.I)
    if m:
        return "suspend", {"pid": int(m.group(1))}

    m = re.match(r'close\s+port\s+(\d+)', t, re.I)
    if m:
        return "close_port", {"port": int(m.group(1))}

    m = re.match(r'quarantine\s+(.+)', t, re.I)
    if m:
        return "quarantine", {"path": m.group(1).strip()}

    m = re.match(r'inspect\s+(.+)', t, re.I)
    if m:
        return "inspect", {"path": m.group(1).strip()}

    if re.match(r'show\s+(?:all\s+)?foreign', t, re.I):
        return "show_foreign", {}

    if re.match(r'show\s+(?:high|critical)', t, re.I):
        return "show_high", {}

    return "ai", {"text": t}

# ── chat processor ────────────────────────────────────────────────────────────

def _build_context(connections: list) -> str:
    header = (
        f"Host: {socket.gethostname()}  Local IP: {get_primary_ip()}  "
        f"Public IP: {get_public_ip()}\nVPN: {get_vpn_status()[0]}\n\n"
        "Active connections (top 30):\n"
        f"{'Process':<20} {'Status':<14} {'Remote IP':<18} {'Country':<16} {'Risk'}\n"
        + "-" * 80
    )
    rows: list[str] = []
    for conn in connections[:30]:
        proc, _, sus = get_proc_info(conn.pid)
        rip    = conn.raddr.ip if conn.raddr else ""
        status = getattr(conn, "status", "NONE") or "NONE"
        risk, _ = calc_risk(conn, suspicious_path=sus)
        country = _geo_cache.get(rip, "?") if rip else "local"
        rows.append(f"{proc:<20} {status:<14} {rip:<18} {country:<16} {risk}")
    return header + "\n" + "\n".join(rows)


build_context_string = _build_context  # alias for run_copilot


def _run_chat_command(state: "ClawState", oc, msg: str) -> str:
    cmd, args = parse_command(msg)
    ts = datetime.now().strftime("%H:%M:%S")

    if cmd == "kill":
        pid = args["pid"]
        ok  = kill_process(pid)
        r   = f"✓ Killed PID {pid}" if ok else f"✗ Failed to kill PID {pid}"
        with state.lock:
            state.action_log.append(f"[{ts}] {r}")
        return r

    if cmd == "block":
        ip = args["ip"]
        ok = block_ip(ip)
        r  = f"✓ Blocked {ip} via firewall" if ok else f"✗ Failed to block {ip}"
        with state.lock:
            state.action_log.append(f"[{ts}] {r}")
        return r

    if cmd == "suspend":
        pid = args["pid"]
        ok  = suspend_process(pid)
        r   = f"✓ Suspended PID {pid}" if ok else f"✗ Failed to suspend PID {pid}"
        with state.lock:
            state.action_log.append(f"[{ts}] {r}")
        return r

    if cmd == "close_port":
        port   = args["port"]
        killed = close_port(port)
        r      = (f"✓ Closed port {port} — killed PID(s): {', '.join(map(str, killed))}"
                  if killed else f"No processes on port {port}")
        with state.lock:
            state.action_log.append(f"[{ts}] {r}")
        return r

    if cmd == "quarantine":
        path = args["path"]
        if not _HAS_SEND2TRASH:
            return "send2trash not installed — pip install send2trash"
        ok = quarantine_file(path)
        r  = f"✓ Moved to Recycle Bin: {path}" if ok else f"✗ Quarantine failed: {path}"
        with state.lock:
            state.action_log.append(f"[{ts}] {r}")
        return r

    if cmd == "inspect":
        info = inspect_file(args["path"])
        if "error" in info:
            return f"✗ {info['error']}"
        return (f"Path:     {info['path']}\n"
                f"Size:     {fmt_bytes(info['size'])}\n"
                f"Modified: {info['modified']}\n"
                f"SHA256:   {info['sha256'][:32]}…")

    if cmd == "show_foreign":
        with state.lock:
            conns = list(state.connections)
        foreign = [c for c in conns if c.raddr and _is_external(c.raddr.ip)]
        if not foreign:
            return "No foreign IP connections right now."
        lines = [f"Found {len(foreign)} foreign connections:"]
        for c in foreign[:12]:
            name, _, _ = get_proc_info(c.pid)
            geo = get_geo(c.raddr.ip)
            lines.append(f"  {name:<18} → {c.raddr.ip:<16} ({geo})")
        return "\n".join(lines)

    if cmd == "show_high":
        with state.lock:
            conns = list(state.connections)
        high = [c for c in conns if calc_risk(c)[0] == "● HIGH"]
        if not high:
            return "No HIGH risk connections right now."
        lines = [f"Found {len(high)} HIGH risk connections:"]
        for c in high[:12]:
            name, _, _ = get_proc_info(c.pid)
            lines.append(f"  {name:<18} → {c.raddr.ip if c.raddr else '—'}")
        return "\n".join(lines)

    # AI fallback
    if oc and oc.available:
        with state.lock:
            conns = list(state.connections)
        return oc.copilot(msg, _build_context(conns))
    return "OpenClaw AI unavailable — set OPENAI_API_KEY to enable."


def _chat_worker(state: "ClawState", oc) -> None:
    while True:
        try:
            msg = state.chat_queue.get(timeout=0.2)
        except queue.Empty:
            continue
        with state.lock:
            state.chat_thinking = True
        try:
            response = _run_chat_command(state, oc, msg)
        except Exception as exc:
            response = f"Error: {exc}"
        with state.lock:
            state.chat_history.append(("AI", response))
            state.chat_thinking = False
            state.chat_scroll   = 0  # auto-scroll to latest response

# ── keyboard input ────────────────────────────────────────────────────────────

def _input_thread(state: "ClawState", oc, tg, live_ref: list) -> None:
    try:
        import msvcrt
    except ImportError:
        return

    while True:
        if not msvcrt.kbhit():
            time.sleep(0.03)
            continue

        ch  = msvcrt.getch()
        ch2 = None
        if ch in (b"\xe0", b"\x00"):
            ch2 = msvcrt.getch()

        changed = False
        with state.lock:
            if state.chat_mode:
                if ch == b"\r":                              # Enter → submit
                    msg = state.chat_input.strip()
                    state.chat_input = ""
                    if msg:
                        state.chat_history.append(("YOU", msg))
                        state.chat_scroll = 0
                        state.chat_queue.put(msg)
                    changed = True
                elif ch == b"\x1b":                          # ESC → exit chat mode
                    state.chat_mode  = False
                    state.chat_input = ""
                    changed = True
                elif ch == b"\x08":                          # Backspace
                    state.chat_input = state.chat_input[:-1]
                    changed = True
                elif ch in (b"\xe0", b"\x00"):               # Special keys — scroll history
                    if ch2 == b"H":                          # ↑ arrow → scroll up
                        state.chat_scroll += 1
                    elif ch2 == b"P":                        # ↓ arrow → scroll down
                        state.chat_scroll = max(0, state.chat_scroll - 1)
                    elif ch2 == b"I":                        # PgUp
                        state.chat_scroll += 5
                    elif ch2 == b"Q":                        # PgDn
                        state.chat_scroll = max(0, state.chat_scroll - 5)
                    changed = True
                else:
                    try:
                        c = ch.decode("utf-8")
                        if c.isprintable():
                            state.chat_input += c
                            changed = True
                    except UnicodeDecodeError:
                        pass
            else:
                total    = len(state.connections)
                max_page = max(0, (total - 1) // state.per_page)
                if ch == b"j":
                    state.page = min(state.page + 1, max_page); changed = True
                elif ch == b"k":
                    state.page = max(0, state.page - 1);        changed = True
                elif ch in (b"\xe0", b"\x00"):               # Arrow keys → scroll connections
                    if ch2 == b"P":  state.page = min(state.page + 1, max_page); changed = True
                    elif ch2 == b"H": state.page = max(0, state.page - 1);       changed = True
                    elif ch2 == b"Q": state.page = min(state.page + 3, max_page); changed = True
                    elif ch2 == b"I": state.page = max(0, state.page - 3);        changed = True
                elif ch in (b"t", b"T"):
                    state.chat_mode  = True
                    state.chat_input = ""
                    changed = True

        if changed:
            live = live_ref[0]
            if live is not None:
                try:
                    live.refresh()
                except Exception:
                    pass

# ── Telegram helpers ──────────────────────────────────────────────────────────

def _execute_tg_action(state: "ClawState", action) -> None:
    execute_action(action.action_type, action.pid, action.remote_ip, state)


def _openclaw_alert_key(ai) -> tuple:
    return (
        "openclaw",
        getattr(ai, "level", ""),
        getattr(ai, "process", ""),
        getattr(ai, "remote", ""),
        getattr(ai, "pid", None),
        getattr(ai, "reason", ""),
    )


def _send_openclaw_alert(tg, level: str, process: str, pid, remote: str,
                         rport="", geo: str = "", reason: str = "",
                         action: str = "monitor") -> None:
    if hasattr(tg, "send_openclaw_alert"):
        tg.send_openclaw_alert(
            level=level,
            process=process,
            pid=pid,
            remote=remote,
            rport=rport,
            geo=geo,
            reason=reason,
            action=action,
        )
        return
    icon = "🔴" if level == "CRITICAL" else "🟡"
    tg.send_alert(
        f"{icon} <b>ClawNet Alert: {level}</b>\n"
        f"Process: <code>{process}</code>  PID: <code>{pid}</code>\n"
        f"IP: <code>{remote}:{rport}</code>  ({geo})\n"
        f"Reason: {reason}\n"
        f"Suggested: <b>{action}</b>\n"
        f"Time: {datetime.now().strftime('%H:%M:%S')}"
    )


def _maybe_telegram_alert(state: "ClawState", connections: list, oc, tg) -> None:
    if tg is None or not getattr(tg, "ready", False):
        return
    for conn in connections:
        ck = _conn_key(conn)
        with state.lock:
            if ck in state.alerted_keys:
                continue
        proc_name, _, suspicious = get_proc_info(conn.pid)
        risk_label, _ = calc_risk(conn, suspicious_path=suspicious)
        ai  = oc.get(ck) if oc and oc.available else None
        rip = conn.raddr.ip   if conn.raddr else ""

        should_alert = False
        alert_level  = ""
        alert_reason = ""

        # AI verdict takes priority
        if ai and not ai.pending:
            if ai.level in ("CRITICAL", "SUSPICIOUS"):
                should_alert = True
                alert_level  = ai.level
                alert_reason = ai.reason

        # Heuristic HIGH — no need to wait for AI
        if not should_alert and risk_label == "● HIGH":
            should_alert = True
            alert_level  = "HIGH"
            alert_reason = "High-risk connection (heuristic)"

        # Suspicious path + foreign connection — alert immediately without AI
        if not should_alert and suspicious and rip and _is_external(rip):
            should_alert = True
            alert_level  = "SUSPICIOUS"
            alert_reason = f"Process running from suspicious path with foreign connection"

        if should_alert:
            ai_key = _openclaw_alert_key(ai) if (ai and not ai.pending) else None
            with state.lock:
                if ck in state.alerted_keys or (ai_key and ai_key in state.alerted_keys):
                    continue
                state.alerted_keys.add(ck)
                if ai_key:
                    state.alerted_keys.add(ai_key)
            rport = conn.raddr.port if conn.raddr else "—"
            geo   = _geo_cache.get(rip, "?") if rip else "—"
            action_text = (ai.action if (ai and not ai.pending) else "monitor")
            _send_openclaw_alert(
                tg, alert_level, proc_name, conn.pid, rip, rport, geo,
                alert_reason, action_text,
            )
    if oc is None or not getattr(oc, "available", False):
        return
    for ai in oc.all_analyses():
        if ai.pending or ai.level not in ("CRITICAL", "SUSPICIOUS"):
            continue
        ai_key = _openclaw_alert_key(ai)
        with state.lock:
            if ai_key in state.alerted_keys:
                continue
            state.alerted_keys.add(ai_key)
        remote = getattr(ai, "remote", "") or ""
        geo = _geo_cache.get(remote, "?") if remote else "—"
        _send_openclaw_alert(
            tg,
            ai.level,
            ai.process,
            ai.pid,
            remote,
            "",
            geo,
            ai.reason,
            ai.action,
        )


def _maybe_auto_respond(connections: list, oc, auto: bool, tg, state: "ClawState") -> None:
    if oc is None or not oc.available:
        return
    for conn in connections:
        ck = _conn_key(conn)
        with state.lock:
            if ck in state.actioned:
                continue
        a = oc.get(ck)
        if not (a and not a.pending and a.level == "CRITICAL" and a.action != "none"):
            continue
        with state.lock:
            state.actioned.add(ck)
        rip = conn.raddr.ip if conn.raddr else ""
        if auto:
            execute_action(a.action, a.pid, rip, state)
        elif tg and getattr(tg, "available", False):
            action_id = f"oc-{conn.pid or 0}-{int(time.time()) % 10000}"
            pa = PendingAction(
                action_id=action_id, pid=a.pid, remote_ip=rip,
                process=a.process, action_type=a.action, reason=a.reason,
            )
            tg.add_pending(pa)


def maybe_request_analysis(connections: list, new_keys: set, oc) -> None:
    if oc is None or not oc.available:
        return
    for conn in connections:
        ck = _conn_key(conn)
        proc_name, exe, suspicious = get_proc_info(conn.pid)
        risk_label, _ = calc_risk(conn, suspicious_path=suspicious)
        if ck not in new_keys and risk_label != "● HIGH" and not suspicious:
            continue
        rip   = conn.raddr.ip   if conn.raddr else ""
        rport = conn.raddr.port if conn.raddr else None
        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        oc.request(ck, {
            "process": proc_name, "exe": exe or "unknown",
            "proto": proto, "status": getattr(conn, "status", "NONE") or "NONE",
            "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—",
            "remote": rip, "rport": rport or "",
            "country": _geo_cache.get(rip, "?") if rip else "local",
            "suspicious": suspicious, "risk": risk_label, "pid": conn.pid,
        })

# ── UI panels ─────────────────────────────────────────────────────────────────

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

    def f(label: str, value: str, vs: str = "white") -> str:
        return f"[bold bright_green]{label}[/]  [{vs}]{value}[/]"

    vpn_warn = "   [dim](⚠ traffic exposed without VPN)[/]" if "NONE" in vpn_label else ""
    row0 = f"[bold bright_green]VPN[/]  [{vpn_style}]{vpn_label}[/]{vpn_warn}"
    row1 = "   ".join([f("HOST", hostname), f("LOCAL", local_ip), f("PUBLIC", pub_ip)])
    row2 = "   ".join([f("WIFI", ssid), f("GW", gateway), f("DNS", dns)])
    row3 = "   ".join([f("TIME", now), f("↑", fmt_bytes(nio.bytes_sent), "cyan"),
                       f("↓", fmt_bytes(nio.bytes_recv), "cyan")])
    body   = "\n".join([row0, row1, row2, row3])
    border = "bold red" if "NONE" in vpn_label else "bright_cyan"
    return Panel(
        Align.center(Text.from_markup(body)),
        border_style=border,
        title="[bold bright_cyan]◈ CLAWNET v2[/]",
        subtitle="[dim]j/k scroll  /  chat  Ctrl+C quit[/dim]",
        padding=(0, 1),
    )


def _ai_flag(oc, conn_key: tuple) -> tuple[str, str]:
    if oc is None or not oc.available:
        return "", ""
    a = oc.get(conn_key)
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
    row_offset: int = 0,
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

    for i, conn in enumerate(connections, row_offset + 1):
        laddr_str = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—"
        rip       = conn.raddr.ip   if conn.raddr else ""
        rport     = conn.raddr.port if conn.raddr else None

        if resolve and rip:
            rhost  = resolve_host(rip)
            remote = f"{rhost}\n[dim]{rip}[/]" if rhost != rip else rip
        else:
            remote = rip or "[dim]—[/dim]"

        status     = getattr(conn, "status", "NONE") or "NONE"
        status_txt = Text(status, style=STATUS_STYLE.get(status, "white"))
        proto      = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        pid_str    = str(conn.pid) if conn.pid else "—"
        port_txt   = (
            Text.from_markup(port_label(rport), style=port_style(rport))
            if rport else Text("—", style="dim")
        )

        proc_name, _, suspicious = get_proc_info(conn.pid)
        proc_display = Text()
        if suspicious:
            proc_display.append("⚠ ", style="bold red")
        proc_display.append(proc_name,
                            style="bold red" if suspicious else "bright_magenta")

        country_txt = Text.from_markup(get_geo(rip) if rip else "[dim]—[/dim]")
        risk_label, risk_style = calc_risk(conn, suspicious_path=suspicious)
        risk_txt = Text(risk_label, style=risk_style)

        ck     = _conn_key(conn)
        is_new = ck in new_keys
        ai_ch, ai_st = _ai_flag(openclaw, ck)

        flags = Text()
        if is_new:     flags.append("★", style="bold yellow")
        if suspicious: flags.append("⚠", style="bold red")
        if ai_ch:      flags.append(ai_ch, style=ai_st)

        table.add_row(
            str(i), flags, risk_txt, proto, status_txt,
            laddr_str, remote, country_txt, port_txt,
            proc_display, pid_str,
            style="on grey7" if is_new else "",
        )
    return table


def build_connections_panel(state: "ClawState", resolve: bool, oc) -> Panel:
    with state.lock:
        conns    = list(state.connections)
        new_keys = set(state.new_keys)
        page     = state.page
        per_page = state.per_page

    total       = len(conns)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page        = min(page, total_pages - 1)
    start       = page * per_page
    end         = min(start + per_page, total)

    table = build_table(
        conns[start:end],
        resolve=resolve,
        new_keys=new_keys,
        openclaw=oc,
        row_offset=start,
    )
    nav = (
        f"[dim]Showing [bold]{start+1}–{end}[/bold] of [bold]{total}[/bold]  │  "
        f"Page [bold]{page+1}[/bold]/[bold]{total_pages}[/bold]  │  "
        f"[bright_cyan]j[/]/[bright_cyan]↓[/] next  "
        f"[bright_cyan]k[/]/[bright_cyan]↑[/] prev  "
        f"[bright_cyan]/[/] chat[/dim]"
    )
    return Panel(
        Group(table, Align.center(Text.from_markup(nav))),
        border_style="bright_black",
        padding=(0, 0),
    )


def build_stats(connections: list) -> Panel:
    status_counts: dict[str, int] = {}
    proc_counts:   dict[str, int] = {}
    risk_counts = {"HIGH": 0, "MED": 0, "LOW": 0}

    for c in connections:
        s = getattr(c, "status", "NONE") or "NONE"
        status_counts[s] = status_counts.get(s, 0) + 1
        name, _, sus = get_proc_info(c.pid)
        proc_counts[name] = proc_counts.get(name, 0) + 1
        label, _ = calc_risk(c, suspicious_path=sus)
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
    body = "\n".join([
        "[bold bright_cyan]RISK SUMMARY[/]",
        f"  [bold red]● HIGH        {risk_counts['HIGH']:>3}[/]",
        f"  [bold yellow]◆ MED         {risk_counts['MED']:>3}[/]",
        f"  [dim green]○ LOW         {risk_counts['LOW']:>3}[/]",
        "", "[bold bright_cyan]BY STATUS[/]",    *status_lines,
        "", "[bold bright_cyan]TOP PROCESSES[/]", *proc_lines,
    ])
    return Panel(body, title="[bold bright_cyan]STATISTICS[/]",
                 border_style="bright_black", padding=(0, 1))


def build_openclaw_panel(oc, tg, state: "ClawState") -> Panel:
    title = "[bold bright_red]⚡ OPENCLAW INTELLIGENCE[/]"
    lines: list[str] = []

    if tg is not None:
        if not getattr(tg, "available", False):
            lines.append("[dim]Telegram: python-telegram-bot not installed[/dim]")
        elif not getattr(tg, "ready", False):
            lines.append(
                "[yellow]Telegram: send [bold]/start[/bold] to your bot to activate alerts[/yellow]"
            )
        else:
            pn = tg.get_pending_count()
            pt = f"  [yellow]⏳ {pn} pending[/yellow]" if pn else ""
            lines.append(f"[dim green]Telegram: {tg.status}{pt}[/dim green]")
        lines.append("")

    if oc is None or not oc.available:
        reason = (
            "[red]openai[/red] not installed" if OpenClaw is None
            else "[yellow]OPENAI_API_KEY[/yellow] not set"
            if not os.environ.get("OPENAI_API_KEY") else "unavailable"
        )
        lines.append(f"[dim]AI analysis disabled — {reason}[/dim]")
        border = "bright_black"
    else:
        analyses   = oc.all_analyses()
        critical   = [a for a in analyses if not a.pending and a.level == "CRITICAL"]
        suspicious = [a for a in analyses if not a.pending and a.level == "SUSPICIOUS"]
        analyzing  = sum(1 for a in analyses if a.pending)

        if analyzing:
            lines.append(f"[dim]Analyzing {analyzing} connection(s)…[/dim]")
        for a in critical[:5]:
            proc   = f"[bold]{a.process}[/]" if a.process else ""
            remote = f" → [dim]{a.remote}[/dim]" if a.remote else ""
            lines.append(
                f"[bold bright_red]● CRITICAL[/] {proc}{remote}\n"
                f"  [dim]{a.reason}[/dim]  [red]→ {a.action}[/red]"
            )
        for a in suspicious[:3]:
            proc   = f"[bold]{a.process}[/]" if a.process else ""
            remote = f" → [dim]{a.remote}[/dim]" if a.remote else ""
            lines.append(
                f"[yellow]◆ SUSPICIOUS[/] {proc}{remote}\n  [dim]{a.reason}[/dim]"
            )
        if not analyses:
            lines.append("[dim]Waiting for connections to analyze…[/dim]")
        elif not critical and not suspicious and not analyzing:
            lines.append("[dim green]✓ No threats detected[/dim green]")

        border = "bold red" if critical else ("yellow" if suspicious else "bright_black")

    with state.lock:
        log = list(state.action_log)
    if log:
        lines += ["", "[bold bright_cyan]REMEDIATION LOG[/]"]
        lines += [f"  [bold cyan]{e}[/]" for e in log[-4:]]

    return Panel("\n".join(lines), title=title, border_style=border, padding=(0, 1))


# Number of history lines visible inside the chat panel (panel size=16 → 14 content rows,
# minus 3 fixed rows for separator + input + hint = 11 for history).
_CHAT_HIST_ROWS = 11


def _wrap_chat_msg(role: str, text: str, inner_width: int) -> list[str]:
    """Return a list of markup-safe lines for one chat message."""
    label  = "YOU" if role == "YOU" else " AI"
    color  = "bright_cyan" if role == "YOU" else "bright_green"
    prefix = f"[bold {color}]  {label}[/]  "
    indent = "       "                              # 7 chars, matches "  XYX  "
    avail  = max(20, inner_width - len(indent) - 2)

    # textwrap on plain text, then escape for Rich markup
    wrapped = textwrap.wrap(text, width=avail, break_long_words=True) or [""]
    result: list[str] = []
    for i, line in enumerate(wrapped):
        safe = _markup_escape(line)
        result.append(f"{prefix}{safe}" if i == 0 else f"{indent}{safe}")
    return result


def build_chat_panel(state: "ClawState", inner_width: int = 76) -> Panel:
    with state.lock:
        history  = list(state.chat_history)
        inp      = state.chat_input
        mode     = state.chat_mode
        thinking = state.chat_thinking
        scroll   = state.chat_scroll

    # ── flatten all history into visual lines ──────────────────────────────
    all_lines: list[str] = []
    for role, text in history:
        all_lines.extend(_wrap_chat_msg(role, text, inner_width))
        all_lines.append("")                        # blank gap between messages

    if thinking:
        all_lines.append("[dim yellow]   ⠿  thinking…[/dim yellow]")

    total = len(all_lines)

    # ── apply scroll window ────────────────────────────────────────────────
    max_scroll = max(0, total - _CHAT_HIST_ROWS)
    scroll     = min(scroll, max_scroll)            # clamp so we never scroll past start

    if total <= _CHAT_HIST_ROWS:
        visible = all_lines + [""] * (_CHAT_HIST_ROWS - total)
    else:
        end   = total - scroll
        start = max(0, end - _CHAT_HIST_ROWS)
        visible = all_lines[start:end]
        # pad if slice is short (e.g. after clamping)
        while len(visible) < _CHAT_HIST_ROWS:
            visible.append("")

    # ── scroll indicator ───────────────────────────────────────────────────
    scroll_tag = ""
    if scroll > 0:
        pct = int(scroll / max(1, max_scroll) * 100)
        scroll_tag = f"  [dim]↑ {pct}% — ↓ to return[/dim]"

    # ── separator ──────────────────────────────────────────────────────────
    sep = "[bright_black]" + "─" * max(10, inner_width) + "[/]"
    visible.append(sep)

    # ── input line ─────────────────────────────────────────────────────────
    if mode:
        cursor   = _blink()
        safe_inp = _markup_escape(inp)
        visible.append(
            f"[bold bright_cyan]  >[/]  {safe_inp}[bright_cyan]{cursor}[/]"
        )
    else:
        if history:
            visible.append(f"[dim]  {len(history)} message(s){scroll_tag}[/dim]")
        else:
            visible.append("[dim]  No messages yet[/dim]")

    # ── hint line ──────────────────────────────────────────────────────────
    if mode:
        visible.append(
            "[dim]  ENTER send  ·  ESC cancel  ·  ↑/↓ scroll history[/dim]"
        )
    else:
        visible.append(
            "[dim]  [bold bright_cyan]T[/] open chat  ·  "
            "[bold bright_cyan]j/k[/] scroll pages  ·  "
            "[bold bright_cyan]↑/↓[/] scroll history[/dim]"
        )

    border = "bright_cyan" if mode else "bright_black"
    title  = "[bold bright_cyan]● CHAT[/]" if mode else "[dim]  CHAT  [/dim]"
    return Panel(
        Text.from_markup("\n".join(visible)),
        title=title,
        border_style=border,
        padding=(0, 1),
    )

# ── background data collector ─────────────────────────────────────────────────

def _data_collector(state: "ClawState", oc, tg, auto: bool) -> None:
    """Gather connections + run analysis in a background thread so the render
    loop stays fast and screen=True doesn't stutter."""
    while True:
        try:
            connections = get_connections()
            new_keys    = update_seen(connections)
            with state.lock:
                state.connections = connections
                state.new_keys    = new_keys
            maybe_request_analysis(connections, new_keys, oc)
            _maybe_auto_respond(connections, oc, auto, tg, state)
            _maybe_telegram_alert(state, connections, oc, tg)
        except Exception:
            pass
        time.sleep(1)

# ── main monitor ──────────────────────────────────────────────────────────────

def run_monitor(resolve: bool = False, auto: bool = False) -> None:
    admin = is_admin()
    state = ClawState()

    mem = None
    if SuperMemory is not None:
        mem = SuperMemory()

    oc = OpenClaw(memory=mem) if OpenClaw is not None else None

    tg_token   = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    tg_chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    tg         = None
    if TelegramAlert is not None and tg_token:
        tg = TelegramAlert(tg_token, tg_chat_id)
        tg.set_execute_callback(lambda a: _execute_tg_action(state, a))
        if TelegramMock is not None and os.environ.get("TELEGRAM_MOCK_ENABLED", "1").lower() in ("1", "true", "yes"):
            TelegramMock(tg).start()

    live_ref: list = [None]

    threading.Thread(target=_fetch_public_ip,                                      daemon=True).start()
    threading.Thread(target=_data_collector,  args=(state, oc, tg, auto),          daemon=True).start()
    threading.Thread(target=_input_thread,    args=(state, oc, tg, live_ref),      daemon=True).start()
    threading.Thread(target=_chat_worker,     args=(state, oc),                    daemon=True).start()

    if not admin:
        console.print(Panel(
            "[yellow]Running without Administrator rights — some process info may be hidden.\n"
            "Run as Administrator for full visibility and action capabilities.[/yellow]",
            border_style="yellow", padding=(0, 1),
        ))
    if not tg_token:
        console.print("[dim]Telegram: TELEGRAM_BOT_TOKEN not set — alerts disabled.[/dim]")

    try:
        with Live(console=console, refresh_per_second=2, screen=False) as live:
            live_ref[0] = live
            while True:
                with state.lock:
                    conns = list(state.connections)

                live.update(Group(
                    Panel(
                        Align.center(Text(BANNER, style="bold bright_cyan")),
                        border_style="bright_cyan",
                        subtitle=(
                            "[dim]AI-Powered Interactive Security Terminal  ·  "
                            "T=chat  j/k=scroll  Ctrl+C=quit[/dim]"
                        ),
                        padding=(0, 0),
                    ),
                    build_header(),
                    build_connections_panel(state, resolve, oc),
                    build_stats(conns),
                    build_openclaw_panel(oc, tg, state),
                    build_chat_panel(state, inner_width=max(40, console.width - 6)),
                ))
                time.sleep(0.5)

    except KeyboardInterrupt:
        pass
    finally:
        console.print("\n[bold bright_cyan]ClawNet terminated.[/]")

# ── copilot mode ──────────────────────────────────────────────────────────────

def run_copilot() -> None:
    oc = OpenClaw() if OpenClaw is not None else None
    console.print(Panel(
        Align.center(Text(BANNER, style="bold bright_cyan")),
        border_style="bright_cyan",
        subtitle="[dim]Security Copilot Mode  |  type 'exit' to quit[/dim]",
        padding=(0, 0),
    ))
    if oc is None or not oc.available:
        console.print(Panel(
            "[yellow]OpenClaw unavailable.[/]\n"
            "Install openai:  [bold]pip install openai[/]\n"
            "Set your key:    [bold]set OPENAI_API_KEY=sk-...[/]",
            border_style="yellow",
        ))
        return
    console.print("[dim]Gathering network snapshot (3 s)…[/dim]")
    threading.Thread(target=_fetch_public_ip, daemon=True).start()
    time.sleep(3)
    connections = get_connections()
    console.print(Rule("[bold bright_cyan]Security Copilot[/]"))
    console.print(
        '[dim]Ask anything. Examples:\n'
        '  "Why is chrome connecting to an unusual IP?"\n'
        '  "Is my system behaving normally?"\n'
        '  "kill pid 1234"  "block 45.33.32.156"[/dim]\n'
    )
    state = ClawState()
    while True:
        try:
            question = Prompt.ask("[bold bright_cyan]>[/]")
        except (KeyboardInterrupt, EOFError):
            break
        if question.strip().lower() in ("exit", "quit", "q"):
            break
        if not question.strip():
            continue
        console.print("[dim]Thinking…[/dim]")
        with state.lock:
            state.connections = connections
        answer = _run_chat_command(state, oc, question)
        console.print(Panel(answer, border_style="bright_cyan", title="[bold]OpenClaw[/]"))
    console.print("\n[bold bright_cyan]Copilot session ended.[/]")


if __name__ == "__main__":
    args = sys.argv[1:]
    if "--copilot" in args:
        run_copilot()
    else:
        threading.Thread(target=_fetch_public_ip, daemon=True).start()
        run_monitor(resolve="--resolve" in args, auto="--auto" in args)
