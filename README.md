<h1 align="center">ClawNet</h1>

<!-- <p align="center"><img width="920" height="171" alt="ClawNet" src="https://github.com/user-attachments/assets/62e1cdf7-c5de-4e5e-8d59-3cabaadc676c" /></p> -->

<p align="center"><img width="920" height="171" alt="ClawNet" src="" /></p>

---

AI-powered network security terminal where a deterministic policy engine scores host traffic and sandboxed code into reproducible verdicts the AI only explains — real-time TCP/UDP monitor + Docker quarantine sandbox with behavioral telemetry, canary exfil detection, a human-gated chain of trust, forensic memory searchable via self-hosted Supermemory Local, Firecrawl threat intel, and a prompt-injection firewall.

It has two defense layers:

- **Live host network monitoring** — every TCP/UDP connection scored in real time
- **Isolation sandbox** — unknown code is quarantined in Docker, watched from the inside, and only reaches your host after passing a full chain of trust

Around them sit an evidence-based forensic memory, a threat-intelligence feed, a human-approval gate on every dangerous action, and an immutable decision log.

> "Nothing runs on the host before ClawNet approves it."

---

# Modes

| Mode | Command | What it does |
|---|---|---|
| Network Monitor | `clawnet` | Live TUI scoring every TCP/UDP connection on your host |
| Copilot | `clawnet --copilot` | AI chat over your current network state |
| Isolation Sandbox | `clawnet --isolation` | Interactive TUI: quarantine and run anything in Docker, monitored from inside |
| Run local project | `clawnet run <path>` | Sandbox a local folder and gate promotion |
| Clone + run | `clawnet clone <url>` | Clone a GitHub repo and sandbox it immediately |
| View past runs | `clawnet sandbox-list [N]` | Table of recent sandbox verdicts |
| Full report | `clawnet sandbox-report <run-id>` | JSON dump of a past sandbox run |
| Policy setup | `clawnet policy-init` | Create/view the sandbox policy file |
| Git interceptors | `clawnet install-interceptors` | Install wrappers that route `git clone` through ClawNet |

---

# How ClawNet decides

The heart of ClawNet is deterministic, not the LLM.

| Component | File | Role |
|---|---|---|
| **Policy Engine** | `core/policy.py` | Collects structured evidence, scores it against explicit rules, and emits the verdict + score + confidence + triggered rules. The only thing that decides. |
| **ClawNet Agent** | `core/clawnet_agent.py` | Reads the verdict and explains it in one sentence. It cannot change the level or action, and an explanation that contradicts the verdict is discarded. |
| **Evidence Memory** | `core/memory.py` | Append-only forensic store of every observation, with lookups and behavior fingerprinting. |
| **Threat Intelligence** | `core/web_search.py` | Crawls public advisories, normalizes CVEs/IOCs, and enriches a verdict before the agent explains it. |
| **Replay Eval** | `core/replay.py` | Records the agent's decision flows and replays them offline for deterministic, $0 CI regression tests. |

**Guardrails & safety:**

- **Prompt-injection firewall** — the LLM only ever receives sanitized JSON evidence, never raw repo files, source, README text, or program output.
- **Action guardrails** — the engine refuses nonsensical or destructive actions: it will not kill protected system processes (`explorer.exe`, `lsass.exe`, ClawNet itself), block private/local IPs, or quarantine Windows system files.
- **Human approval gate** — kill process, block IP, and quarantine file always require explicit approval before execution. `--auto` does **not** bypass this.
- **Immutable decision log** — every verdict, refusal, approval, and executed action is appended to `~/.clawnet/decisions.jsonl` for audit and replay.

---

# Network Monitor (host-side)

A live Rich TUI, refreshed continuously, showing exactly what your machine is talking to and why.

### System dashboard

| Field | Source |
|---|---|
| VPN status | Interface scan each tick (WireGuard, OpenVPN, TAP, PPP, Cisco, …). Border turns red when no tunnel is active. |
| Host / Local IP | Hostname and primary interface IP |
| Public IP | External IP via background fetch to `api.ipify.org`, cached 60s |
| WiFi SSID / Gateway / DNS | `netsh` / `ipconfig` (Windows) |
| Bytes sent / received | Cumulative interface throughput |

### Connection table

One row per active connection: **FLAGS** (`~` analyzing, `C/S` critical/suspicious verdict, `✓` safe), **RISK**, **PROTO**, **STATUS**, **LOCAL**, **REMOTE**, **COUNTRY** (GeoIP), **PORT**, **PROCESS**, **PID**. New connections (seen within 6s) are highlighted.

### Deterministic risk scoring

Risk is **not** a simple port table — it is the policy engine's rule set over collected evidence (executable path & SHA-256, parent process, remote IP/port, GeoIP, listen exposure, reputation memory, and threat-intel hits):

| Rule | Points |
|---|---|
| Binary runs from a volatile drop zone (`Temp`, `Downloads`, `Desktop`, …) | +3 |
| Drop-zone binary spawned by a shell (`cmd`, `powershell`, `wscript`, …) | +2 |
| Drop-zone binary talking to the internet | +2 |
| Dangerous remote port (Telnet 23, 4444, RDP 3389, 5900, …) | +2–4 |
| Sensitive service port (SSH, SMTP, MySQL, Postgres, Redis, Mongo) | +2 |
| Foreign SYN_SENT beacon pattern | +2 |
| Live foreign connection / listening on `0.0.0.0` / untrusted dir | +1 each |
| Previously flagged CRITICAL / SUSPICIOUS in memory | +3 / +1 |

Scores map to **SAFE**, **SUSPICIOUS** (≥3), and **CRITICAL** (≥6). Binaries under `AppData\Roaming` / `AppData\Local` (npm globals, Slack, VS Code) are treated as user-installed software, not drop zones — so the tool doesn't cry wolf on every CLI you have installed.

Every verdict carries its **score, confidence, and the exact rules that fired** — type `explain <pid>` to see the full evidence trail.

### Actions

Typed commands (`kill <pid>`, `block <ip>`, `suspend <pid>`, `quarantine <path>`, `close port <n>`) run through the guardrails above. CRITICAL connections queue a remediation for your approval — in Telegram if configured, otherwise surfaced in the log with the command to run. Nothing is killed or blocked without a human saying so.

---

# Isolation Sandbox

Unknown code is analyzed **without ever touching your working tree**.

### Quarantine lifecycle

```
clawnet --isolation <src>
  -> copy src into ~/.clawnet/quarantine/<id>/     (isolated staging — your tree is never mounted)
  -> docker run against the copy, behavioral telemetry from inside
  -> Chain of Trust + human approval
  -> PASS + approve -> copy the vetted snapshot to $CLAWNET_HOST_WORKSPACE/<name>/
  -> FAIL / decline -> left in quarantine, nothing reaches your host
```

What you promote is byte-for-byte what was tested.

### Behavioral telemetry (from inside the container)

`core/container_agent.py` runs as the supervisor inside the sandbox and collects, straight from `/proc` (no `ps`, no extra capabilities):

- Process tree and full ancestry chains (`sh > npm > node > curl`)
- Package installs (pip / npm / yarn / pnpm / cargo / go / apt / apk …)
- **Install-time code execution** (postinstall scripts, `setup.py`, node-gyp, native compilation)
- Sensitive-file access, proven with **planted decoy credentials** and a **per-run canary** (a fake secret; if that value ever leaves the process, it was stolen)
- Persistence attempts (cron, systemd, `rc.local`, shell profiles, `ld.so.preload`)
- Privilege escalation, environment/secret theft, and foreign network egress

The agent holds **no host credentials** — it writes findings to a log and the host raises the alerts.

### Docker hardening

`--cap-drop ALL` · `--security-opt no-new-privileges` · seccomp · CPU / memory / PID / file-descriptor limits · swap disabled · read-only workspace · tmpfs for every writable path · Docker socket and host env vars never mounted. Denied secrets are blanked; expected secret names are replaced with canaries so theft is detectable. Backends are pluggable — gVisor and Kata slot in via a config line (`runtime`).

### Chain of Trust

A project reaches the host only after passing every step:

```
Behavior Report -> Policy Engine -> Signature Verification -> SBOM
   -> Dependency Scan -> Threat Intelligence Lookup -> Human Approval -> Promote
```

Blocking steps (policy DANGEROUS, known-malicious dependency, threat-intel IOC hit) cannot be overridden by the human. The engine builds an SBOM (declared vs. actually-installed packages), scans for known-bad/typosquat and undeclared installs, verifies the HEAD commit signature, and looks up egress IPs and packages against threat intelligence.

### Behavior scoring

Behavioral evidence is scored deterministically and mapped to **SAFE** (0–34), **SUSPICIOUS** (35–69), **DANGEROUS** (70–100). Renamed malware is still caught — a **behavior fingerprint** (process trees, network behavior, accessed-file categories, install managers, persistence, independent of filenames) matches a prior run even under a fresh name and hash.

---

# Evidence Memory

`core/memory.py` is a forensic store, not "AI memory" — it holds deterministic evidence, never LLM opinions.

- **Append-only timeline** (`~/.clawnet/evidence.jsonl`): repeated runs of the same binary or repo build history instead of overwriting.
- **Full forensic snapshots** of every sandbox run: SHA-256, exe path, process tree, remote IPs, ports, network behavior, file access, persistence, installed dependencies, signature status, triggered rules, score, verdict, timestamp.
- **Lookup APIs**: `lookup_sha256 / process / ip / domain / repository / dependency / behavior`, plus `timeline()` and `historical_context()`.
- **Enrichment**: before analyzing anything new, memory is searched for matching hashes, IPs, behaviors, or fingerprints, and the agent's explanation cites what it found ("previously observed 3×, same behavioral fingerprint, worst prior verdict CRITICAL").

The agent **only queries** memory; writes originate exclusively from the deterministic engine.

---

# Threat Intelligence

`core/web_search.py` is the single integration point for web crawling and Supermemory Local.

- Crawls trusted public sources (CISA KEV, NVD, MITRE ATT&CK, GitHub Advisories, MSRC, vendor malware reports) via **Firecrawl** (free tier).
- Normalizes each document into structured evidence: CVE IDs, IOCs (IPs / domains / URLs / hashes), affected software, CVSS, exploit availability, publication date, source, summary. Never stores arbitrary LLM text.
- Persists it in **Supermemory Local** for semantic search, and exposes clean helpers: `enrich_ip / enrich_domain / enrich_hash / enrich_url / enrich_package`, `search_memory`, `get_recent_cves`.
- Feeds the policy engine before a verdict and the chain-of-trust threat-intel step. A configured-but-down server never stalls a verdict — a cheap reachability probe falls back to the local crawl cache instantly.

---

# Behavior Detection Signals (inside the sandbox)

| Signal | Points |
|---|---|
| Canary secret exfiltrated | +50 |
| Planted decoy credential read | +45 |
| Reverse shell / cryptominer | +40 |
| `curl … \| bash` remote-exec pipe | +35 |
| Wallet / cloud / SSH credential access | +25–35 |
| Persistence write (cron, systemd, profiles) | +30 |
| Privilege escalation attempt | +30 |
| Install-time code execution | +25 |
| Foreign egress (per external host) | +10 |
| System package install (apt/apk) | +15 |
| Package install command | +5 |

---

# Tech Stack

**Core runtime** — Python 3.11+, psutil, subprocess, socket, Rich TUI

**Decision layer** — deterministic policy engine (`policy.py`), ClawNet agent (`clawnet_agent.py`, GPT-4o-mini for explanations only), replay eval (`replay.py`)

**Memory & intel** — append-only JSONL evidence store, Supermemory Local, Firecrawl

**Isolation** — Docker CLI, `container_agent.py`, pluggable backends (gVisor / Kata ready)

---

# Installation

```bash
git clone https://github.com/rajarshidattapy/clawnet.git
cd clawnet

python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

pip install -r core/requirements.txt
```

---

# Environment Variables

Create a `.env` file in the repo root. Every integration is optional:

```env
# AI explanations (optional — verdicts work without it)
OPENAI_API_KEY=your_openai_key

# Telegram alerts + approvals (optional)
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
CLAWNET_TELEGRAM_APPROVAL=1

# Threat intelligence (optional)
FIRECRAWL_API_KEY=your_firecrawl_key

# Supermemory Local — semantic evidence/threat search (optional)
SUPERMEMORY_API_KEY=sm_...
SUPERMEMORY_API_URL=http://localhost:6767

# Where approved sandbox projects are promoted (default ~/clawnet-workspace)
CLAWNET_HOST_WORKSPACE=/path/to/workspace
```

With nothing configured, the policy engine, sandbox, evidence memory, and decision log all still work fully offline.

---

# Prerequisites

**Docker** (for the sandbox):

```bash
docker --version && docker ps
```

ClawNet auto-pulls `python:3.11-slim` on first sandbox run — no Dockerfile or compose needed.

**Supermemory Local** (optional, for semantic search) is a Linux binary, so on Windows it runs inside WSL via `bunx`:

```bash
bash scripts/supermemory-local.sh      # starts bunx supermemory local in WSL, serves :6767
```

The printed `sm_...` key goes into `.env`. Without it, ClawNet's JSONL evidence store remains the source of truth.

---

# Run ClawNet

### Network Monitor

```bash
python clawnet.py    # or: clawnet
```

| Key | Action |
|---|---|
| `T` | Open chat / copilot |
| `j` / `k` | Scroll |
| `Ctrl+C` | Quit |

Chat commands: `explain <pid>`, `kill <pid>`, `block <ip>`, `suspend <pid>`, `quarantine <path>`, `show foreign`, `show high`.

### Isolation Sandbox

```bash
clawnet --isolation                 # interactive menu
clawnet run ./my-project --deep     # sandbox a local folder
clawnet clone https://github.com/someone/project.git --cmd "python main.py"
```

### Sandbox reports

```bash
clawnet sandbox-list 50
clawnet sandbox-report sbx-1748123456
```

### End-to-end demo

```bash
python tests/sandbox_demo.py        # builds a harmless-but-suspicious repo and runs the whole pipeline
```

---

# Risk Levels

**Sandbox (behavioral score):**

| Score | Level | Outcome |
|---|---|---|
| 0–34 | SAFE | Promotion allowed (with approval) |
| 35–69 | SUSPICIOUS | Manual review required |
| 70–100 | DANGEROUS | Auto-blocked, stays in quarantine |

**Network (policy score):** `SAFE` · `SUSPICIOUS` (≥3) · `CRITICAL` (≥6) — CRITICAL queues a human-approved remediation.

---

# Sandbox Policy

```bash
clawnet policy-init
```

```json
{
  "max_runtime_seconds": 300,
  "cpu_limit": "1.5",
  "memory_limit": "1536m",
  "pids_limit": 256,
  "network_mode": "bridge",
  "read_only_workspace": true,
  "enable_telemetry": true,
  "block_on_foreign_egress": true,
  "plant_decoy_credentials": true,
  "require_signature": false,
  "backend": "docker",
  "runtime": "",
  "deny_env_keys": ["OPENAI_API_KEY", "SUPERMEMORY_API_KEY", "TELEGRAM_BOT_TOKEN", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"],
  "canary_env_keys": ["AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "OPENAI_API_KEY", "NPM_TOKEN"]
}
```

---

# Project Structure

```text
clawnet/
├── core/
│   ├── clawnet.py            # network monitor TUI + CLI dispatch
│   ├── clawnet_agent.py      # AI analyst — explains verdicts, never decides
│   ├── policy.py             # deterministic policy engine + guardrails + decision log
│   ├── memory.py             # append-only forensic evidence store
│   ├── web_search.py         # threat intelligence (Firecrawl + Supermemory Local)
│   ├── replay.py             # deterministic record/replay evaluation
│   ├── sandbox.py            # quarantine, hardening, chain of trust
│   ├── container_agent.py    # in-container behavioral telemetry
│   ├── isolation.py          # sandbox TUI
│   ├── telegram_alert.py     # alerts + approval flow
│   ├── netwatch.py           # legacy standalone monitor
│   └── requirements.txt
├── tests/                    # policy self-checks, threat-intel tests, replay cassette, sandbox demo
├── scripts/                  # supermemory-local.sh
├── docs/
├── clawnet.py                # launcher
├── pyproject.toml
└── .env
```

---

# Testing

```bash
python core/policy.py        # policy engine + guardrails + injection firewall self-check
python core/memory.py        # evidence store + fingerprinting self-check
python core/replay.py score  # deterministic ship / no-ship eval (offline, $0)
python -m pytest tests/      # full regression suite (policy + threat intelligence)
```

Every check runs offline at $0 — no API key, no network, no Docker required.

---

# Security Model

1. Detect suspicious behavior deterministically
2. Isolate unknown code in a quarantined container
3. Monitor it from inside the runtime
4. Score behavior with the policy engine (AI only explains)
5. Gate every dangerous action behind a human
6. Promote to the host only after the full chain of trust
7. Log every decision immutably

---

# Vision

ClawNet is evolving into a full autonomous runtime-defense system — answering not just *"what is happening?"* but *"what caused it, how dangerous is it, and should the system act automatically?"* — an AI-native, policy-gated security layer for local machines, containers, and CI/CD pipelines.

---

# Future Scope

eBPF runtime instrumentation · autonomous GitHub remediation PRs · threat-graph visualization · distributed sandbox fleet · WASM / Firecracker sandbox runtimes · additional threat-intel providers (VirusTotal, AbuseIPDB, OTX, URLHaus).

---

# License

MIT License

---

# Disclaimer

ClawNet is a defensive security platform for malware analysis, runtime inspection, infrastructure protection, incident response, and the safe execution of untrusted code. Users are responsible for complying with local laws and organizational security policies.
