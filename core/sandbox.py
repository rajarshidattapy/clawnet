#!/usr/bin/env python3
"""ClawNet sandbox runtime: run unknown projects in Docker before host trust."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from html import escape as _html_escape
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

try:
    import openai as _openai
except ImportError:
    _openai = None

try:
    from memory import SuperMemory, make_event
except ImportError:
    from core.memory import SuperMemory, make_event

try:
    from telegram_alert import TelegramAlert
except ImportError:
    from core.telegram_alert import TelegramAlert

console = Console()

_SUSPICIOUS_PATTERNS: dict[str, tuple[str, int]] = {
    r"\b(private key|seed phrase|mnemonic)\b": ("Wallet key material reference", 30),
    r"\b(\.ssh|id_rsa|known_hosts)\b": ("SSH material access reference", 25),
    r"\b(curl|wget).*(pastebin|ngrok|discord|telegram)\b": ("Potential exfiltration endpoint", 25),
    r"\b(chmod\s+\+x|powershell\s+-enc|base64\s+-d)\b": ("Obfuscated/suspicious execution pattern", 20),
    r"\b(xmrig|miner|stratum\+tcp)\b": ("Possible cryptominer behavior", 35),
    r"\b(ufw|iptables|netsh).*(disable|off)\b": ("Firewall tampering attempt", 25),
    r"\b(adduser|useradd|sudoers)\b": ("Privilege persistence pattern", 20),
}

_DEFAULT_IMAGE = "python:3.11-slim"
_MAX_LOG_BYTES = 200_000
_REPUTATION_PATH = Path.home() / ".clawnet" / "sandbox_reputation.json"
_POLICY_PATH = Path.home() / ".clawnet" / "sandbox_policy.json"
_MAX_FINGERPRINT_FILES = 300
_MAX_FINGERPRINT_FILE_SIZE = 512 * 1024

_DEFAULT_POLICY: dict[str, Any] = {
    "max_runtime_seconds": 300,
    "cpu_limit": "1.5",
    "memory_limit": "1536m",
    "pids_limit": 256,
    "network_mode": "bridge",  # bridge | none
    "read_only_workspace": True,
    "enable_telemetry": True,
    "telemetry_interval_seconds": 2,
    "block_on_foreign_egress": True,
    "foreign_egress_risk_bonus": 30,
    "deny_env_keys": [
        "OPENAI_API_KEY",
        "SUPERMEMORY_API_KEY",
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_CHAT_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
    ],
}


@dataclass
class SandboxResult:
    target: str
    run_id: str
    sandbox_dir: str
    stdout_path: str
    stderr_path: str
    metadata_path: str
    exit_code: int
    timed_out: bool
    risk_score: int
    risk_level: str
    reasons: list[str]
    recommendation: str
    ai_reason: str = ""


def _safe_read(path: Path, limit: int = _MAX_LOG_BYTES) -> str:
    try:
        with path.open("rb") as f:
            data = f.read(limit)
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _looks_like_git_url(target: str) -> bool:
    return bool(re.match(r"^(https://|git@|ssh://).+\.git$", target.strip()))


def _detect_start_command(workspace: Path) -> str:
    if (workspace / "requirements.txt").exists():
        if (workspace / "main.py").exists():
            return "pip install -r requirements.txt && python main.py"
        if (workspace / "app.py").exists():
            return "pip install -r requirements.txt && python app.py"
        return "pip install -r requirements.txt && python -m pytest -q || true"
    if (workspace / "pyproject.toml").exists():
        return "pip install -e . && python -m pytest -q || true"
    if (workspace / "package.json").exists():
        return "npm install && npm run start || npm run dev || npm test || true"
    return "ls -la && echo 'No known runtime entrypoint found.'"


def _load_policy() -> dict[str, Any]:
    if not _POLICY_PATH.exists():
        return dict(_DEFAULT_POLICY)
    try:
        raw = json.loads(_POLICY_PATH.read_text(encoding="utf-8"))
        policy = dict(_DEFAULT_POLICY)
        policy.update(raw if isinstance(raw, dict) else {})
        return policy
    except Exception:
        return dict(_DEFAULT_POLICY)


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True


def _hex_ipv4_to_str(hex_ip: str) -> str:
    # /proc/net/tcp stores IPv4 in little-endian hex
    if len(hex_ip) != 8:
        return ""
    try:
        b = bytes.fromhex(hex_ip)
        return ".".join(str(x) for x in b[::-1])
    except Exception:
        return ""


def _extract_foreign_ips_from_proc_net(log_text: str) -> list[str]:
    ips: set[str] = set()
    for line in log_text.splitlines():
        parts = line.split()
        if len(parts) < 3 or ":" not in parts[2]:
            continue
        rem = parts[2]
        hex_ip, _hex_port = rem.split(":", 1)
        ip = _hex_ipv4_to_str(hex_ip)
        if ip and not _is_private_ip(ip) and ip != "0.0.0.0":
            ips.add(ip)
    return sorted(ips)


def _build_container_script(user_command: str, telemetry_interval: int) -> str:
    safe_cmd = user_command.replace("\"", "\\\"")
    return (
        "set +e;"
        "export DEBIAN_FRONTEND=noninteractive;"
        "mkdir -p /clawnet-out;"
        "echo '[clawnet] sandbox start' > /clawnet-out/runtime.log;"
        "START_TS=$(date +%s);"
        "if [ -n \"" + str(telemetry_interval) + "\" ]; then "
        "(while true; do "
        "date +%s >> /clawnet-out/proc-sample.log; "
        "ps -eo pid,ppid,comm,%cpu,%mem,args >> /clawnet-out/proc-sample.log 2>/dev/null; "
        "echo '---' >> /clawnet-out/proc-sample.log; "
        "cat /proc/net/tcp >> /clawnet-out/net-sample.log 2>/dev/null; "
        "cat /proc/net/tcp6 >> /clawnet-out/net-sample.log 2>/dev/null; "
        "echo '---' >> /clawnet-out/net-sample.log; "
        f"sleep {max(1, telemetry_interval)}; "
        "done) & "
        "MON_PID=$!; "
        "fi;"
        "sh -lc \"" + safe_cmd + "\" > /clawnet-out/stdout.log 2> /clawnet-out/stderr.log;"
        "RC=$?;"
        "END_TS=$(date +%s);"
        "DUR=$((END_TS-START_TS));"
        "if [ -n \"$MON_PID\" ]; then kill $MON_PID >/dev/null 2>&1; fi;"
        "printf '{\"duration_sec\":%s,\"exit_code\":%s}\\n' \"$DUR\" \"$RC\" > /clawnet-out/runtime-meta.json;"
        "exit $RC"
    )


def _heuristic_risk(stdout: str, stderr: str, metadata: dict) -> tuple[int, list[str]]:
    combined = f"{stdout}\n{stderr}".lower()
    score = 0
    reasons: list[str] = []
    for pattern, (reason, delta) in _SUSPICIOUS_PATTERNS.items():
        if re.search(pattern, combined, flags=re.IGNORECASE):
            score += delta
            reasons.append(reason)
    if metadata.get("timed_out"):
        score += 10
        reasons.append("Execution timeout reached")
    if metadata.get("exit_code", 0) not in (0,):
        score += 5
        reasons.append("Process exited with non-zero status")
    foreign_ips = metadata.get("foreign_egress_ips", []) or []
    if foreign_ips:
        score += int(metadata.get("foreign_egress_bonus", 30))
        reasons.append(f"Observed foreign egress IPs: {', '.join(foreign_ips[:3])}")
    score = min(100, score)
    return score, reasons


def _score_to_level(score: int) -> str:
    if score >= 70:
        return "DANGEROUS"
    if score >= 35:
        return "SUSPICIOUS"
    return "SAFE"


def _default_recommendation(level: str) -> str:
    if level == "DANGEROUS":
        return "block_promotion"
    if level == "SUSPICIOUS":
        return "manual_review"
    return "allow_promotion"


def _ai_sandbox_verdict(stdout: str, stderr: str, score: int, reasons: list[str]) -> tuple[Optional[str], Optional[str]]:
    if _openai is None or not os.environ.get("OPENAI_API_KEY"):
        return None, None
    client = _openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    summary = (
        f"Heuristic risk score: {score}\n"
        f"Heuristic reasons: {', '.join(reasons) if reasons else 'none'}\n\n"
        f"STDOUT (truncated):\n{stdout[:5000]}\n\n"
        f"STDERR (truncated):\n{stderr[:5000]}"
    )
    system = (
        "You are a security sandbox analyst. "
        "Classify the run risk and return strict JSON only.\n"
        "{\"level\":\"SAFE|SUSPICIOUS|DANGEROUS\",\"reason\":\"<=20 words\",\"recommendation\":\"allow_promotion|manual_review|block_promotion\"}"
    )
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        max_tokens=150,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": summary},
        ],
    )
    text = resp.choices[0].message.content.strip()
    s, e = text.find("{"), text.rfind("}") + 1
    if s < 0 or e <= s:
        return None, None
    try:
        data = json.loads(text[s:e])
        return str(data.get("level", "")).upper(), str(data.get("reason", ""))
    except Exception:
        return None, None


class SandboxRunner:
    def __init__(self) -> None:
        self._mem = SuperMemory() if SuperMemory is not None else None
        self.ensure_policy_file()

    def ensure_policy_file(self) -> Path:
        if not _POLICY_PATH.exists():
            _POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
            _POLICY_PATH.write_text(json.dumps(_DEFAULT_POLICY, indent=2), encoding="utf-8")
        return _POLICY_PATH

    def clone_and_run(
        self,
        git_url: str,
        runtime_command: str = "",
        deep_scan: bool = False,
        force_network_mode: str = "",
    ) -> SandboxResult:
        if not _looks_like_git_url(git_url):
            raise ValueError("Expected a git URL ending with .git")
        clone_root = Path(tempfile.mkdtemp(prefix="clawnet-clone-"))
        target = clone_root / "repo"
        subprocess.run(
            ["git", "clone", "--depth", "1", git_url, str(target)],
            capture_output=True,
            text=True,
            check=True,
        )
        try:
            return self.run_target(
                str(target),
                runtime_command=runtime_command,
                deep_scan=deep_scan,
                force_network_mode=force_network_mode,
            )
        finally:
            shutil.rmtree(clone_root, ignore_errors=True)

    def run_target(
        self,
        target_path: str,
        runtime_command: str = "",
        deep_scan: bool = False,
        force_network_mode: str = "",
    ) -> SandboxResult:
        workspace = Path(target_path).resolve()
        if not workspace.exists():
            raise FileNotFoundError(f"Target path not found: {workspace}")
        if shutil.which("docker") is None:
            raise RuntimeError("Docker CLI not found in PATH.")

        run_id = f"sbx-{int(time.time())}"
        sandbox_dir = Path(tempfile.mkdtemp(prefix=f"clawnet-{run_id}-"))
        stdout_path = sandbox_dir / "stdout.log"
        stderr_path = sandbox_dir / "stderr.log"
        proc_sample_path = sandbox_dir / "proc-sample.log"
        net_sample_path = sandbox_dir / "net-sample.log"
        runtime_meta_path = sandbox_dir / "runtime-meta.json"
        metadata_path = sandbox_dir / "metadata.json"
        policy = _load_policy()
        if force_network_mode in ("none", "bridge"):
            policy["network_mode"] = force_network_mode
        fingerprint = self._fingerprint_target(workspace)
        reputation = self._load_reputation()
        rep_key = str(workspace).lower()
        prior = reputation.get(rep_key, {})

        if (
            not deep_scan
            and prior.get("fingerprint") == fingerprint
            and prior.get("risk_level") == "SAFE"
            and prior.get("approved") is True
        ):
            meta = {
                "target": str(workspace),
                "run_id": run_id,
                "runtime_command": runtime_command.strip() or _detect_start_command(workspace),
                "exit_code": 0,
                "timed_out": False,
                "stdout_sha256": "",
                "stderr_sha256": "",
                "ts": int(time.time()),
                "risk_score": 0,
                "risk_level": "SAFE",
                "reasons": ["Trusted cache hit: unchanged fingerprint"],
                "recommendation": "allow_promotion",
                "ai_reason": "Previously approved safe run and unchanged target fingerprint",
                "fingerprint": fingerprint,
                "cache_hit": True,
            }
            metadata_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            self._print_report(meta, stdout_path, stderr_path)
            return SandboxResult(
                target=str(workspace),
                run_id=run_id,
                sandbox_dir=str(sandbox_dir),
                stdout_path=str(stdout_path),
                stderr_path=str(stderr_path),
                metadata_path=str(metadata_path),
                exit_code=0,
                timed_out=False,
                risk_score=0,
                risk_level="SAFE",
                reasons=["Trusted cache hit: unchanged fingerprint"],
                recommendation="allow_promotion",
                ai_reason=meta["ai_reason"],
            )

        user_command = runtime_command.strip() or _detect_start_command(workspace)
        container_script = _build_container_script(
            user_command,
            telemetry_interval=int(policy.get("telemetry_interval_seconds", 2)),
        )
        container_name = f"clawnet-{run_id}"
        deny_env_keys = set(policy.get("deny_env_keys", []))

        cmd = [
            "docker", "run", "--rm",
            "--name", container_name,
            "--cpus", str(policy.get("cpu_limit", "1.5")),
            "--memory", str(policy.get("memory_limit", "1536m")),
            "--pids-limit", str(policy.get("pids_limit", 256)),
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--network", str(policy.get("network_mode", "bridge")),
            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m",
            "--tmpfs", "/run:rw,nosuid,nodev,size=16m",
            "--tmpfs", "/var/tmp:rw,nosuid,nodev,size=16m",
            "-v", f"{workspace}:/workspace:{'ro' if policy.get('read_only_workspace', True) else 'rw'}",
            "-v", f"{sandbox_dir}:/clawnet-out:rw",
            "-w", "/workspace",
            "--pull", "missing",
        ]
        if policy.get("read_only_workspace", True):
            cmd.append("--read-only")
        for key in deny_env_keys:
            cmd.extend(["-e", f"{key}="])
        cmd.extend([
            _DEFAULT_IMAGE,
            "sh", "-lc", container_script,
        ])

        timed_out = False
        exit_code = 0
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=int(policy.get("max_runtime_seconds", 300)),
            )
            exit_code = int(proc.returncode)
            if not stdout_path.exists():
                stdout_path.write_text(proc.stdout or "", encoding="utf-8")
            if not stderr_path.exists():
                stderr_path.write_text(proc.stderr or "", encoding="utf-8")
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            exit_code = 124
            if not stdout_path.exists():
                stdout_path.write_text(exc.stdout or "", encoding="utf-8")
            if not stderr_path.exists():
                stderr_path.write_text((exc.stderr or "") + "\n[clawnet] timed out", encoding="utf-8")
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, text=True)

        stdout = _safe_read(stdout_path)
        stderr = _safe_read(stderr_path)
        net_sample = _safe_read(net_sample_path)
        foreign_ips = _extract_foreign_ips_from_proc_net(net_sample)
        runtime_meta = {}
        try:
            if runtime_meta_path.exists():
                runtime_meta = json.loads(runtime_meta_path.read_text(encoding="utf-8"))
        except Exception:
            runtime_meta = {}
        meta = {
            "target": str(workspace),
            "run_id": run_id,
            "runtime_command": user_command,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "stdout_sha256": _sha256_text(stdout),
            "stderr_sha256": _sha256_text(stderr),
            "ts": int(time.time()),
            "fingerprint": fingerprint,
            "cache_hit": False,
            "policy": policy,
            "foreign_egress_ips": foreign_ips,
            "foreign_egress_bonus": int(policy.get("foreign_egress_risk_bonus", 30)),
            "telemetry_paths": {
                "proc_sample": str(proc_sample_path),
                "net_sample": str(net_sample_path),
                "runtime_meta": str(runtime_meta_path),
            },
            "runtime_meta": runtime_meta,
        }
        score, reasons = _heuristic_risk(stdout, stderr, meta)
        level = _score_to_level(score)
        recommendation = _default_recommendation(level)
        ai_reason = ""

        ai_level, ai_reason_candidate = _ai_sandbox_verdict(stdout, stderr, score, reasons)
        if ai_level in ("SAFE", "SUSPICIOUS", "DANGEROUS"):
            level = ai_level
            recommendation = _default_recommendation(level)
            ai_reason = ai_reason_candidate or ""

        if policy.get("block_on_foreign_egress", True) and meta.get("foreign_egress_ips"):
            if level == "SAFE":
                level = "SUSPICIOUS"
                recommendation = "manual_review"
            if len(meta["foreign_egress_ips"]) >= 3:
                level = "DANGEROUS"
                recommendation = "block_promotion"
            if not ai_reason:
                ai_reason = "Foreign outbound egress observed during sandbox runtime"

        meta.update(
            {
                "risk_score": score,
                "risk_level": level,
                "reasons": reasons,
                "recommendation": recommendation,
                "ai_reason": ai_reason,
            }
        )
        metadata_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

        self._store_memory(meta)
        self._maybe_telegram_alert(meta)
        self._print_report(meta, stdout_path, stderr_path)

        return SandboxResult(
            target=str(workspace),
            run_id=run_id,
            sandbox_dir=str(sandbox_dir),
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            metadata_path=str(metadata_path),
            exit_code=exit_code,
            timed_out=timed_out,
            risk_score=score,
            risk_level=level,
            reasons=reasons,
            recommendation=recommendation,
            ai_reason=ai_reason,
        )

    def promotion_gate(self, result: SandboxResult) -> bool:
        approved = False
        if result.risk_level == "DANGEROUS":
            console.print("[bold red]Promotion blocked: DANGEROUS verdict.[/bold red]")
            approved = False
        elif result.risk_level == "SAFE":
            console.print("[bold green]SAFE verdict: promotion allowed.[/bold green]")
            approved = True
        else:
            approved = self._approval_for_suspicious(result)
        self._update_reputation(result, approved=approved)
        return approved

    def _approval_for_suspicious(self, result: SandboxResult) -> bool:
        token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
        use_telegram = os.environ.get("CLAWNET_TELEGRAM_APPROVAL", "0").lower() in ("1", "true", "yes")
        if use_telegram and token and chat_id:
            tg = TelegramAlert(token, chat_id)
            if getattr(tg, "ready", False):
                try:
                    tg.send_alert(
                        "<b>ClawNet Approval Required</b>\n"
                        f"Target: <code>{_html_escape(result.target)}</code>\n"
                        f"Risk: <b>{_html_escape(result.risk_level)}</b>\n"
                        "Reply in chat: <code>approve</code> or <code>deny</code> within 120s."
                    )
                    decision = self._wait_telegram_decision(tg, timeout_sec=120)
                    if decision is not None:
                        return decision
                except Exception:
                    pass
        answer = input("Verdict is SUSPICIOUS. Promote to host anyway? [y/N]: ").strip().lower()
        return answer in ("y", "yes")

    def _wait_telegram_decision(self, tg: "TelegramAlert", timeout_sec: int = 120) -> Optional[bool]:
        start = time.time()
        offset = 0
        while time.time() - start < timeout_sec:
            updates = tg.get_updates(offset=offset)
            for u in updates:
                offset = max(offset, int(u.get("update_id", 0)) + 1)
                text = ((u.get("message") or {}).get("text") or "").strip().lower()
                if text in ("approve", "/approve", "yes", "y"):
                    return True
                if text in ("deny", "/deny", "no", "n"):
                    return False
            time.sleep(2)
        return None

    def _fingerprint_target(self, workspace: Path) -> str:
        """Compute a stable lightweight fingerprint for trust cache decisions."""
        hasher = hashlib.sha256()
        files_seen = 0
        for root, dirs, files in os.walk(workspace):
            dirs[:] = [d for d in dirs if d not in (".git", ".venv", "venv", "node_modules", "__pycache__")]
            for name in sorted(files):
                if files_seen >= _MAX_FINGERPRINT_FILES:
                    break
                path = Path(root) / name
                try:
                    st = path.stat()
                    rel = path.relative_to(workspace).as_posix()
                    hasher.update(rel.encode("utf-8"))
                    hasher.update(str(st.st_size).encode("utf-8"))
                    hasher.update(str(int(st.st_mtime)).encode("utf-8"))
                    if st.st_size <= _MAX_FINGERPRINT_FILE_SIZE and rel.endswith(
                        (".py", ".js", ".ts", ".tsx", ".json", ".toml", ".yaml", ".yml", ".sh", ".md", "Dockerfile")
                    ):
                        try:
                            hasher.update(path.read_bytes())
                        except Exception:
                            pass
                    files_seen += 1
                except Exception:
                    continue
            if files_seen >= _MAX_FINGERPRINT_FILES:
                break
        hasher.update(str(files_seen).encode("utf-8"))
        return hasher.hexdigest()

    def _load_reputation(self) -> dict:
        try:
            if _REPUTATION_PATH.exists():
                return json.loads(_REPUTATION_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {}

    def _save_reputation(self, rep: dict) -> None:
        try:
            _REPUTATION_PATH.parent.mkdir(parents=True, exist_ok=True)
            _REPUTATION_PATH.write_text(json.dumps(rep, indent=2), encoding="utf-8")
        except Exception:
            pass

    def install_interceptors(self) -> list[str]:
        """Install lightweight wrappers to encourage sandbox-first workflows."""
        base = Path.home() / ".clawnet" / "interceptors"
        base.mkdir(parents=True, exist_ok=True)
        installed: list[str] = []

        git_cmd = base / "git-clone-through-clawnet.cmd"
        git_cmd.write_text(
            "@echo off\r\n"
            "if /I \"%1\"==\"clone\" (\r\n"
            "  clawnet clone %2 --deep\r\n"
            ") else (\r\n"
            "  git %*\r\n"
            ")\r\n",
            encoding="utf-8",
        )
        installed.append(str(git_cmd))

        ps1 = base / "Invoke-ClawnetRun.ps1"
        ps1.write_text(
            "param([string]$Path,[string]$Cmd='')\n"
            "if ($Cmd -eq '') { clawnet run $Path --deep } else { clawnet run $Path --cmd $Cmd --deep }\n",
            encoding="utf-8",
        )
        installed.append(str(ps1))
        return installed

    def _update_reputation(self, result: SandboxResult, approved: bool) -> None:
        try:
            meta = json.loads(Path(result.metadata_path).read_text(encoding="utf-8"))
        except Exception:
            meta = {
                "target": result.target,
                "risk_level": result.risk_level,
                "risk_score": result.risk_score,
                "recommendation": result.recommendation,
                "fingerprint": "",
            }
        rep = self._load_reputation()
        rep_key = str(result.target).lower()
        rep[rep_key] = {
            "target": str(result.target),
            "fingerprint": meta.get("fingerprint", ""),
            "risk_level": meta.get("risk_level", result.risk_level),
            "risk_score": meta.get("risk_score", result.risk_score),
            "recommendation": meta.get("recommendation", result.recommendation),
            "approved": bool(approved),
            "updated_at": int(time.time()),
            "ai_reason": meta.get("ai_reason", result.ai_reason),
        }
        self._save_reputation(rep)

    def _store_memory(self, meta: dict) -> None:
        if not self._mem:
            return
        try:
            event = make_event(
                level=meta.get("risk_level", "SUSPICIOUS"),
                reason=(meta.get("ai_reason") or "; ".join(meta.get("reasons", [])[:2]) or "sandbox analysis"),
                action=meta.get("recommendation", "manual_review"),
                process="sandbox-runtime",
                remote_ip="",
                port=0,
                exe=meta.get("target", ""),
            )
            self._mem.store_event(event)
        except Exception:
            pass

    def _maybe_telegram_alert(self, meta: dict) -> None:
        token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
        if not token:
            return
        try:
            tg = TelegramAlert(token, chat_id)
            if not getattr(tg, "ready", False):
                return
            level = meta.get("risk_level", "SUSPICIOUS")
            if level == "SAFE":
                return
            reason = meta.get("ai_reason") or ", ".join(meta.get("reasons", [])[:2]) or "sandbox flagged behavior"
            if meta.get("foreign_egress_ips"):
                reason = f"{reason}; egress={','.join(meta['foreign_egress_ips'][:3])}"
            tg.send_clawnet_alert(
                level=level,
                process=f"sandbox:{Path(meta.get('target', '')).name}",
                pid=None,
                remote="",
                reason=reason,
                action=meta.get("recommendation", "manual_review"),
            )
        except Exception:
            pass

    def _print_report(self, meta: dict, stdout_path: Path, stderr_path: Path) -> None:
        table = Table(title="ClawNet Sandbox Report")
        table.add_column("Field", style="bold cyan")
        table.add_column("Value", style="white")
        table.add_row("Target", str(meta.get("target", "")))
        table.add_row("Run ID", str(meta.get("run_id", "")))
        table.add_row("Risk Score", str(meta.get("risk_score", 0)))
        table.add_row("Risk Level", str(meta.get("risk_level", "UNKNOWN")))
        table.add_row("Recommendation", str(meta.get("recommendation", "")))
        table.add_row("Exit Code", str(meta.get("exit_code", "")))
        table.add_row("Timed Out", str(meta.get("timed_out", False)))
        table.add_row("Cache Hit", str(meta.get("cache_hit", False)))
        table.add_row("STDOUT Log", str(stdout_path))
        table.add_row("STDERR Log", str(stderr_path))
        if meta.get("telemetry_paths"):
            tp = meta["telemetry_paths"]
            table.add_row("Telemetry (proc)", str(tp.get("proc_sample", "")))
            table.add_row("Telemetry (net)", str(tp.get("net_sample", "")))
        if meta.get("foreign_egress_ips"):
            table.add_row("Foreign Egress", ", ".join(meta.get("foreign_egress_ips", [])[:5]))
        if meta.get("ai_reason"):
            table.add_row("AI Reason", str(meta["ai_reason"]))
        if meta.get("reasons"):
            table.add_row("Heuristic Signals", "; ".join(meta["reasons"]))
        console.print(table)
        if meta.get("risk_level") == "DANGEROUS":
            console.print(Panel("DANGEROUS run detected. Host promotion is denied.", border_style="red"))
