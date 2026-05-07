#!/usr/bin/env python3
"""ClawNet container agent — executes INSIDE the Docker sandbox.

This is the only ClawNet code that runs inside the container.
It acts as a supervisor: starts the target command as a subprocess,
monitors /proc/net for foreign IPs in real time, scans output lines
for suspicious patterns, and fires Telegram pings immediately on findings.

Only stdlib dependencies — works in any Python 3.8+ base image.
"""

import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

_OUT = Path("/clawnet-out")
_CFG = Path("/clawnet-agent/config.json")
_POLL_SEC = 1
_PROC_SEC = 2

_PATTERNS: dict = {
    r"\b(private key|seed phrase|mnemonic)\b": ("Wallet key material reference", 30),
    r"\b(\.ssh|id_rsa|known_hosts)\b": ("SSH material access reference", 25),
    r"\b(curl|wget).*(pastebin|ngrok|discord|telegram)\b": ("Potential exfiltration endpoint", 25),
    r"\b(chmod\s+\+x|base64\s+-d)\b": ("Obfuscated/suspicious execution pattern", 20),
    r"\b(xmrig|miner|stratum\+tcp)\b": ("Possible cryptominer behavior", 35),
    r"\b(adduser|useradd|sudoers)\b": ("Privilege persistence pattern", 20),
    r"\b(pip|pip3)\s+install\b": ("Package installation detected", 8),
    r"\b(npm|yarn|pnpm)\s+install\b": ("Node package installation detected", 8),
    r"\b(apt-get|apt|apk)\s+install\b": ("System package installation detected", 15),
    r"\bprintenv\b": ("Environment variable enumeration", 15),
    r"/proc/\d+/environ": ("Process environment file read", 20),
    r"\b(curl|wget|fetch).*\|\s*(bash|sh|python3?|ruby|perl)\b": ("Remote code execution pipe", 30),
    r"\bcrontab\b": ("Cron job modification attempt", 20),
    r"\b(systemctl|service)\s+enable\b": ("Service persistence attempt", 20),
    r"\b(nc|ncat|netcat)\s+.*-(e|l)\b": ("Reverse shell / listener pattern", 35),
    r"\bchmod\s+[0-9]*7[0-9]*\b": ("Broad permission grant on file", 12),
    r"\b(ssh-keyscan|ssh-copy-id)\b": ("SSH key distribution attempt", 25),
}


# ── helpers ───────────────────────────────────────────────────────────────────

def _load_cfg() -> dict:
    try:
        return json.loads(_CFG.read_text())
    except Exception:
        return {}


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True


def _hex_to_ipv4(h: str) -> str:
    if len(h) != 8:
        return ""
    try:
        return ".".join(str(x) for x in bytes.fromhex(h)[::-1])
    except Exception:
        return ""


def _parse_proc_net(path: str) -> set:
    ips: set = set()
    try:
        with open(path) as f:
            next(f, None)  # skip header
            for line in f:
                parts = line.split()
                if len(parts) < 3 or ":" not in parts[2]:
                    continue
                hex_ip = parts[2].split(":")[0]
                ip = _hex_to_ipv4(hex_ip)
                if ip and ip != "0.0.0.0" and not _is_private(ip):
                    ips.add(ip)
    except Exception:
        pass
    return ips


def _tg_send(token: str, chat_id: str, text: str) -> None:
    if not token or not chat_id:
        return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    body = urllib.parse.urlencode(
        {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    ).encode()
    try:
        req = urllib.request.Request(url, data=body)
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        urllib.request.urlopen(req, timeout=8)
    except Exception:
        pass


def _log_alert(tag: str, detail: str) -> None:
    try:
        with (_OUT / "live-alerts.log").open("a") as f:
            f.write(f"{time.time():.0f} {tag} {detail}\n")
    except Exception:
        pass


# ── shared state ──────────────────────────────────────────────────────────────

class _State:
    def __init__(self, cfg: dict) -> None:
        self.token: str = cfg.get("telegram_token", "")
        self.chat_id: str = cfg.get("telegram_chat_id", "")
        self.target: str = cfg.get("target_name", "unknown")
        self.known_ips: set = set()
        self.signals: list = []
        self.score: int = 0
        self.done: bool = False
        self._lock = threading.Lock()

    def ping(self, text: str) -> None:
        _tg_send(self.token, self.chat_id, text)

    def new_ip(self, ip: str) -> bool:
        with self._lock:
            if ip in self.known_ips:
                return False
            self.known_ips.add(ip)
        return True

    def add_signal(self, reason: str, delta: int) -> bool:
        """Returns True if the signal is new and caused a score threshold cross."""
        with self._lock:
            if reason in self.signals:
                return False
            old = self.score
            self.signals.append(reason)
            self.score = min(100, self.score + delta)
            # report if we just crossed 35 (SUSPICIOUS) or 70 (DANGEROUS)
            return (old < 35 <= self.score) or (old < 70 <= self.score)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "score": self.score,
                "signals": list(self.signals),
                "ips": sorted(self.known_ips),
            }


# ── background monitors ───────────────────────────────────────────────────────

def _net_monitor(state: _State) -> None:
    """Poll /proc/net every second; Telegram-ping on first sight of any foreign IP."""
    while not state.done:
        for path in ("/proc/net/tcp", "/proc/net/tcp6",
                     "/proc/net/udp", "/proc/net/udp6"):
            for ip in _parse_proc_net(path):
                if state.new_ip(ip):
                    _log_alert("FOREIGN_IP", ip)
                    state.ping(
                        f"<b>ClawNet — Live Foreign Egress</b>\n"
                        f"Target: <code>{state.target}</code>\n"
                        f"New outbound IP detected: <code>{ip}</code>\n"
                        f"Time: {time.strftime('%H:%M:%S')}"
                    )
        time.sleep(_POLL_SEC)


def _proc_monitor(state: _State) -> None:
    """Sample process list; write to telemetry; scan for suspicious process names."""
    while not state.done:
        try:
            out = subprocess.check_output(
                ["ps", "-eo", "pid,ppid,comm,args"],
                text=True, stderr=subprocess.DEVNULL, timeout=3,
            )
            try:
                with (_OUT / "proc-sample.log").open("a") as f:
                    f.write(f"--- {time.time():.0f} ---\n{out}\n")
            except Exception:
                pass
            for pattern, (reason, delta) in _PATTERNS.items():
                if re.search(pattern, out, re.IGNORECASE):
                    crossed = state.add_signal(reason, delta)
                    if crossed:
                        snap = state.snapshot()
                        state.ping(
                            f"<b>ClawNet — Risk Threshold Crossed</b>\n"
                            f"Target: <code>{state.target}</code>\n"
                            f"New Signal: {reason}\n"
                            f"Risk Score: <b>{snap['score']}</b>\n"
                            f"Time: {time.strftime('%H:%M:%S')}"
                        )
        except Exception:
            pass
        time.sleep(_PROC_SEC)


def _scan_output_line(line: str, state: _State) -> None:
    """Scan a single line of app stdout for suspicious patterns."""
    for pattern, (reason, delta) in _PATTERNS.items():
        if re.search(pattern, line, re.IGNORECASE):
            crossed = state.add_signal(reason, delta)
            _log_alert("SIGNAL", reason.replace(" ", "_"))
            if crossed:
                snap = state.snapshot()
                state.ping(
                    f"<b>ClawNet — Suspicious Output Detected</b>\n"
                    f"Target: <code>{state.target}</code>\n"
                    f"Signal: {reason}\n"
                    f"Risk Score: <b>{snap['score']}</b>\n"
                    f"Output: <code>{line[:120]}</code>"
                )


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) < 2:
        print("[clawnet-agent] No command provided.", file=sys.stderr)
        sys.exit(1)

    command = sys.argv[1]
    _OUT.mkdir(parents=True, exist_ok=True)

    cfg = _load_cfg()
    state = _State(cfg)

    # Start background monitors
    threading.Thread(target=_net_monitor, args=(state,), daemon=True).start()
    threading.Thread(target=_proc_monitor, args=(state,), daemon=True).start()

    state.ping(
        f"<b>ClawNet — Sandbox Started</b>\n"
        f"Target: <code>{state.target}</code>\n"
        f"Command: <code>{command[:120]}</code>\n"
        f"Live monitoring active. You will be pinged on any finding."
    )

    start_ts = time.time()
    exit_code = 0

    try:
        proc = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        for line in proc.stdout:
            print(line, end="", flush=True)
            _scan_output_line(line, state)
        proc.wait()
        exit_code = proc.returncode or 0
    except Exception as exc:
        print(f"[clawnet-agent] Error: {exc}", file=sys.stderr)
        exit_code = 1
    finally:
        state.done = True

    duration = round(time.time() - start_ts, 1)
    snap = state.snapshot()
    score = snap["score"]
    level = "SAFE" if score < 35 else ("SUSPICIOUS" if score < 70 else "DANGEROUS")

    meta = {
        "duration_sec": duration,
        "exit_code": exit_code,
        "risk_score": score,
        "risk_level": level,
        "signals": snap["signals"],
        "foreign_ips": snap["ips"],
    }
    try:
        (_OUT / "agent-meta.json").write_text(json.dumps(meta, indent=2))
    except Exception:
        pass

    # Final Telegram summary (only if anything was found)
    if score > 0 or snap["ips"]:
        lines = [f"<b>ClawNet — Sandbox Complete</b>"]
        lines.append(f"Target: <code>{state.target}</code>")
        lines.append(f"Risk Level: <b>{level}</b>   Score: {score}")
        lines.append(f"Duration: {duration}s   Exit: {exit_code}")
        if snap["signals"]:
            lines.append("\nSignals detected:")
            for s in snap["signals"][:6]:
                lines.append(f"  • {s}")
        if snap["ips"]:
            lines.append(f"\nForeign egress IPs: <code>{', '.join(snap['ips'][:5])}</code>")
        state.ping("\n".join(lines))

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
