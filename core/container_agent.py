#!/usr/bin/env python3
"""ClawNet container agent — executes INSIDE the Docker sandbox.

The only ClawNet code that runs inside the container. It supervises the target
command and collects *behavioral* telemetry, then writes it to /clawnet-out for
the host to score with the deterministic policy engine.

What it collects (all from /proc — no ps, no strace, no extra capabilities):
  · process tree + full ancestry chains (parent -> child -> grandchild)
  · package installs (pip/npm/yarn/pnpm/cargo/go/apt/apk/gem/composer)
  · install-time code execution (postinstall, setup.py, node-gyp, cc/make)
  · sensitive file access, via open file descriptors + planted decoy files
  · persistence attempts (cron, systemd, rc.local, shell profiles, ld.so.preload)
  · privilege escalation attempts (sudo/su/setuid/capsh)
  · environment/secret theft, via canary values planted in the environment
  · foreign network egress (/proc/net)

It never gets host credentials: the agent writes findings to a log and the HOST
sends the alerts. A malicious target that reads every file in this container
still finds no token to steal.

Only stdlib — works in any Python 3.8+ base image.
"""

import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

_OUT = Path("/clawnet-out")
_CFG = Path("/clawnet-agent/config.json")
_POLL_SEC = 1.0

# ── what we consider sensitive, in-container ──────────────────────────────────

_SENSITIVE_FILES = {
    "ssh_key":         r"(\.ssh/|id_rsa|id_ed25519|authorized_keys|known_hosts)",
    "cloud_cred":      r"(\.aws/credentials|\.config/gcloud|\.azure/|\.kube/config)",
    "env_file":        r"(^|/)\.env(\.|$)",
    "git_cred":        r"(\.git-credentials|\.netrc|\.npmrc|\.pypirc)",
    "docker_cred":     r"\.docker/config\.json",
    "browser_profile": r"(Cookies|Login Data|\.mozilla/|Chrome/User Data)",
    "system_secret":   r"(/etc/shadow|/etc/sudoers)",
    "proc_environ":    r"/proc/\d+/environ",
    "wallet":          r"(wallet\.dat|keystore|\.electrum)",
}

# Files that must not change. A write here is a persistence attempt.
_PERSISTENCE_PATHS = [
    "/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/rc.local",
    "/etc/systemd/system", "/etc/ld.so.preload", "/etc/profile",
    "/root/.bashrc", "/root/.profile", "/root/.bash_profile",
]

_PKG_MANAGERS = {
    "pip": "pip", "pip3": "pip", "uv": "pip", "poetry": "pip", "easy_install": "pip",
    "npm": "npm", "yarn": "npm", "pnpm": "npm", "npx": "npm",
    "cargo": "cargo", "go": "go", "gem": "gem", "composer": "composer",
    "apt": "apt", "apt-get": "apt", "apk": "apk", "dnf": "apt", "yum": "apt",
}

# Things that should never be running as a *child of an installer*.
_INSTALL_EXEC = re.compile(
    r"(^|/)(sh|bash|dash|zsh|node|python\d?|ruby|perl|make|cc|gcc|g\+\+|node-gyp|"
    r"cmake|setup\.py|prebuild-install)(\s|$)"
)

_ESCALATION = re.compile(r"(^|/)(sudo|su|capsh|setcap|chmod\s+[0-7]*[4-7]7[0-7]*|pkexec)(\s|$)")

_SHELL_NAMES = {"sh", "bash", "dash", "zsh", "ash"}

# Behaviors we can spot in a command line regardless of ancestry.
_CMD_SIGNALS = {
    r"\b(curl|wget|fetch)\b.*\|\s*(bash|sh|python3?|ruby|perl)": "remote_exec_pipe",
    r"\b(xmrig|stratum\+tcp|minerd|cpuminer)\b":                 "cryptominer",
    r"\b(nc|ncat|netcat)\s+.*-(e|l)\b":                          "reverse_shell",
    r"\b(base64\s+-d|openssl\s+enc|eval\s+\$\()":                "obfuscated_exec",
    r"\bcrontab\b":                                              "cron_persistence",
    r"\b(systemctl|service)\s+enable\b":                         "service_persistence",
    r"\b(printenv|env)\s*$":                                     "env_enumeration",
    r"\b(useradd|adduser|usermod)\b":                            "account_persistence",
    r"\b(iptables|ufw)\b.*\b(flush|disable|off)\b":              "firewall_tampering",
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
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) < 3 or ":" not in parts[2]:
                    continue
                ip = _hex_to_ipv4(parts[2].split(":")[0])
                if ip and ip != "0.0.0.0" and not _is_private(ip):
                    ips.add(ip)
    except Exception:
        pass
    return ips


def _log_alert(tag: str, detail: str) -> None:
    """The host tails this file and raises the Telegram alert — we hold no creds."""
    try:
        with (_OUT / "live-alerts.log").open("a") as f:
            f.write(f"{time.time():.0f} {tag} {detail}\n")
    except Exception:
        pass


# ── /proc readers (no ps binary needed — slim images do not have one) ─────────

def _read_procs() -> dict:
    """pid -> {ppid, comm, cmdline}. Straight from /proc, no dependencies."""
    procs: dict = {}
    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
    except Exception:
        return procs
    for pid in pids:
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
            # comm is wrapped in parens and may itself contain spaces
            rparen = stat.rfind(")")
            comm   = stat[stat.find("(") + 1:rparen]
            ppid   = int(stat[rparen + 2:].split()[1])
            raw    = Path(f"/proc/{pid}/cmdline").read_bytes()
            cmd    = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
            procs[int(pid)] = {"ppid": ppid, "comm": comm, "cmdline": cmd or comm}
        except Exception:
            continue
    return procs


def _open_files(pid: int) -> list:
    """Currently-open files for a pid, via /proc/<pid>/fd symlinks."""
    out = []
    try:
        for fd in os.listdir(f"/proc/{pid}/fd"):
            try:
                out.append(os.readlink(f"/proc/{pid}/fd/{fd}"))
            except Exception:
                continue
    except Exception:
        pass
    return out


def _ancestry(procs: dict, pid: int) -> list:
    """Walk pid -> ppid to the root. Returns ['sh', 'npm', 'node', 'curl']."""
    chain, seen = [], set()
    while pid and pid not in seen and pid in procs:
        seen.add(pid)
        chain.append(procs[pid]["comm"])
        pid = procs[pid]["ppid"]
    return list(reversed(chain))


def _parse_install(cmdline: str) -> dict:
    """Recognise a package install command and pull the package names out.

    Scans the first few tokens for the manager name, not just argv[0]: pip is
    usually invoked as `python /usr/local/bin/pip install ...`, so the manager
    is the *second* token, and npm/yarn are shell-wrapped just as often.
    """
    parts = cmdline.split()
    if not parts:
        return {}
    mgr = None
    for tok in parts[:3]:
        mgr = _PKG_MANAGERS.get(os.path.basename(tok))
        if mgr:
            break
    if not mgr:
        return {}
    verbs = {"install", "add", "i", "get", "ci"}
    verb_idx = next((i for i, p in enumerate(parts) if p in verbs), -1)
    if verb_idx < 0:
        return {}
    # Packages are the non-flag tokens after the verb, up to the first shell
    # operator (the install may be one command in a chained `sh -c "a; b"`).
    # Skip the filename a flag consumes (-r requirements.txt, -c constraints.txt).
    pkgs, skip = [], False
    for p in parts[verb_idx + 1:]:
        if p in (";", "|", "&", "&&", "||", ">", ">>", "2>&1") or any(c in p for c in ";|&<>"):
            break
        if skip:
            skip = False
            continue
        if p in ("-r", "-c", "--requirement", "--constraint"):
            skip = True
            continue
        if not p.startswith("-"):
            pkgs.append(p)
    return {"manager": mgr, "command": cmdline[:200], "packages": pkgs[:30]}


# ── decoy files: nothing real to steal, but reading them proves intent ────────

def _plant_decoys(canary: str) -> dict:
    """Plant fake credentials. Opening one is unambiguous — no app needs these."""
    decoys = {
        "/root/.ssh/id_rsa": f"-----BEGIN OPENSSH PRIVATE KEY-----\n{canary}\n",
        "/root/.aws/credentials": f"[default]\naws_secret_access_key = {canary}\n",
        "/root/.env": f"API_KEY={canary}\n",
        "/root/.git-credentials": f"https://x-access-token:{canary}@github.com\n",
    }
    planted = {}
    for path, body in decoys.items():
        try:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
            planted[str(p.resolve())] = True
        except Exception:
            continue
    return planted


# ── shared state ──────────────────────────────────────────────────────────────

class _State:
    def __init__(self, cfg: dict) -> None:
        self.target: str = cfg.get("target_name", "unknown")
        self.canary: str = cfg.get("canary", "")
        self.known_ips: set = set()
        self.processes: dict = {}      # dedup key -> record
        self.lineage: set = set()      # "a > b > c"
        self.installs: dict = {}       # command -> record
        self.install_exec: dict = {}
        self.file_access: dict = {}    # path -> category
        self.persistence: set = set()
        self.escalation: set = set()
        self.signals: set = set()
        self.decoys_read: set = set()
        self.canary_leaked: bool = False
        self.done: bool = False
        self._lock = threading.Lock()

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "processes":     list(self.processes.values()),
                "lineage":       sorted(self.lineage),
                "installs":      list(self.installs.values()),
                "install_exec":  list(self.install_exec.values()),
                "file_access":   [{"path": p, "category": c} for p, c in self.file_access.items()],
                "decoys_read":   sorted(self.decoys_read),
                "canary_leaked": self.canary_leaked,
                "persistence":   sorted(self.persistence),
                "escalation":    sorted(self.escalation),
                "signals":       sorted(self.signals),
                "foreign_ips":   sorted(self.known_ips),
            }


# ── monitors ─────────────────────────────────────────────────────────────────

def _net_monitor(state: _State) -> None:
    while not state.done:
        for path in ("/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"):
            for ip in _parse_proc_net(path):
                with state._lock:
                    if ip in state.known_ips:
                        continue
                    state.known_ips.add(ip)
                _log_alert("FOREIGN_IP", ip)
        time.sleep(_POLL_SEC)


def _behavior_monitor(state: _State, decoys: dict) -> None:
    """The heart of the telemetry: sample /proc, build lineage, classify behavior."""
    baseline = _persistence_mtimes()

    while not state.done:
        procs = _read_procs()
        for pid, p in procs.items():
            cmd   = p["cmdline"]
            chain = _ancestry(procs, pid)
            key   = f"{p['comm']}|{cmd}"

            with state._lock:
                if key not in state.processes:
                    state.processes[key] = {
                        "pid": pid, "ppid": p["ppid"], "comm": p["comm"],
                        "cmdline": cmd[:300], "ancestry": chain, "ts": int(time.time()),
                    }
                if len(chain) > 1:
                    state.lineage.add(" > ".join(chain))

            # installs
            inst = _parse_install(cmd)
            if inst:
                with state._lock:
                    if inst["command"] not in state.installs:
                        state.installs[inst["command"]] = inst
                        _log_alert("INSTALL", f"{inst['manager']}:{','.join(inst['packages'][:5])}")

            # install-time code execution: a shell/compiler running *under* an installer
            installer_in_chain = [c for c in chain[:-1] if c in _PKG_MANAGERS]
            if installer_in_chain and _INSTALL_EXEC.search(cmd) and p["comm"] not in _PKG_MANAGERS:
                ident = " > ".join(chain)
                with state._lock:
                    if ident not in state.install_exec:
                        state.install_exec[ident] = {
                            "installer": installer_in_chain[-1],
                            "executed": cmd[:200],
                            "ancestry": chain,
                        }
                        _log_alert("INSTALL_EXEC", f"{installer_in_chain[-1]} spawned {p['comm']}")

            # privilege escalation
            if _ESCALATION.search(cmd):
                with state._lock:
                    state.escalation.add(cmd[:160])

            # command-line signals
            for pattern, name in _CMD_SIGNALS.items():
                if re.search(pattern, cmd, re.IGNORECASE):
                    with state._lock:
                        state.signals.add(name)

            # canary theft: the secret value appearing in any argv is exfil in progress
            if state.canary and state.canary in cmd:
                with state._lock:
                    state.canary_leaked = True
                _log_alert("CANARY_LEAK", "canary secret found in a command line")

            # sensitive file access via open fds.
            # ponytail: fd-sampling at _POLL_SEC catches sustained access (read +
            # hold, the real exfil pattern). A microsecond open/close can slip
            # through — the planted canary is the reliable backstop for that case.
            for path in _open_files(pid):
                if path in decoys:
                    with state._lock:
                        state.decoys_read.add(path)
                    _log_alert("DECOY_READ", path)
                for category, pattern in _SENSITIVE_FILES.items():
                    if re.search(pattern, path, re.IGNORECASE):
                        with state._lock:
                            state.file_access[path] = category
                        break

        # persistence: did any protected file change?
        for path, mtime in _persistence_mtimes().items():
            if baseline.get(path) != mtime:
                with state._lock:
                    state.persistence.add(path)
                _log_alert("PERSISTENCE", path)
        time.sleep(_POLL_SEC)


def _persistence_mtimes() -> dict:
    out = {}
    for path in _PERSISTENCE_PATHS:
        try:
            out[path] = Path(path).stat().st_mtime
        except Exception:
            out[path] = None
    return out


def _scan_output_line(line: str, state: _State) -> None:
    """The app printing the canary means it read a decoy and is echoing it out."""
    if state.canary and state.canary in line:
        with state._lock:
            state.canary_leaked = True
        _log_alert("CANARY_LEAK", "canary secret appeared in program output")
    for pattern, name in _CMD_SIGNALS.items():
        if re.search(pattern, line, re.IGNORECASE):
            with state._lock:
                if name not in state.signals:
                    state.signals.add(name)
                    _log_alert("SIGNAL", name)


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) < 2:
        print("[clawnet-agent] No command provided.", file=sys.stderr)
        sys.exit(1)

    command = sys.argv[1]
    _OUT.mkdir(parents=True, exist_ok=True)

    cfg   = _load_cfg()
    state = _State(cfg)
    decoys = _plant_decoys(state.canary) if state.canary else {}

    threading.Thread(target=_net_monitor,      args=(state,),         daemon=True).start()
    threading.Thread(target=_behavior_monitor, args=(state, decoys),  daemon=True).start()

    start_ts  = time.time()
    exit_code = 0
    try:
        proc = subprocess.Popen(
            command, shell=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1,
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

    time.sleep(_POLL_SEC)          # let the samplers flush one last pass
    report = state.snapshot()
    report["duration_sec"] = round(time.time() - start_ts, 1)
    report["exit_code"]    = exit_code
    report["target"]       = state.target

    try:
        (_OUT / "behavior.json").write_text(json.dumps(report, indent=2))
    except Exception:
        pass

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
