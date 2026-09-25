<h1 align="center">ClawNet</h1>

<!-- <p align="center"><img width="920" height="171" alt="ClawNet" src="https://github.com/user-attachments/assets/62e1cdf7-c5de-4e5e-8d59-3cabaadc676c" /></p> -->

<p align="center"><img width="920" height="171" alt="ClawNet" src="https://github.com/user-attachments/assets/c52a108c-7107-480f-ac85-ec269ce112a3" /></p>

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

# ClawNet — Architecture & Repository Guide

ClawNet is a Python security terminal for Windows hosts. It has two defense layers:

1. **Network Monitor.** A live Rich TUI that scores every TCP/UDP connection on the host.
2. **Isolation Sandbox.** It copies unknown code into quarantine, runs it in a hardened Docker container, watches it from the inside, and copies it to the host only after it passes a full chain of trust and a human approves it.

The core design rule: **a deterministic policy engine makes every decision, and the LLM only explains it.** The LLM is a local Ollama model (`qwen3:8b` by default). It receives sanitized JSON evidence only. It cannot change a verdict or an action, and the system discards any explanation that contradicts the verdict.

- Package: `clawnet` v3.0.0 (`pyproject.toml`), Python ≥ 3.10 (the README says 3.11+)
- Entry point: `clawnet = "clawnet:main"` → `clawnet.py` (root launcher)
- Runtime dependencies: `psutil`, `rich`, `python-telegram-bot`, `send2trash`, plus the optional `supermemory`
- About 9.9k lines in total. The largest files are `core/sandbox.py` (1668 lines) and `core/clawnet.py` (1512 lines).

---

## 1. Repository layout

```text
clawnet/
├── clawnet.py                 # Root launcher / CLI dispatcher (main())
├── pyproject.toml             # Packaging; exposes `clawnet` console script
├── .env.example               # All env vars (every one optional)
├── README.md                  # User-facing docs
├── core/
│   ├── __init__.py            # empty
│   ├── clawnet.py             # Network monitor TUI, copilot, chat commands, host actions
│   ├── policy.py              # Deterministic policy engine, guardrails, injection firewall, decision log
│   ├── clawnet_agent.py       # AI analyst: explains verdicts (never decides)
│   ├── llm.py                 # Only LLM transport: Ollama /api/chat via urllib
│   ├── memory.py              # Append-only forensic evidence store (JSONL) + behavior fingerprints
│   ├── web_search.py          # Threat intel: Firecrawl crawl → normalize → Supermemory Local + cache
│   ├── replay.py              # Record/replay cassette + adversarial ship/no-ship scoring
│   ├── sandbox.py             # SandboxRunner: quarantine, hardened docker run, scoring, chain of trust
│   ├── container_agent.py     # Runs INSIDE the container: /proc behavioral telemetry
│   ├── isolation.py           # Interactive sandbox TUI (`--isolation`)
│   ├── telegram_alert.py      # Telegram alerts + approval flow (urllib) + mock generator
│   ├── netwatch.py            # Legacy standalone monitor (NETWATCH v1.0); not wired into the launcher
│   └── requirements.txt
├── tests/
│   ├── test_policy.py         # Policy/guardrail/replay regression (offline)
│   ├── test_web_search.py     # Threat-intel normalization/enrichment with a fake client
│   ├── sandbox_demo.py        # End-to-end Docker demo with a "suspicious" repo
│   └── recordings/clawnet.json# Replay cassette (fixtures + recorded explanations)
├── scripts/
│   └── supermemory-local.sh   # Starts `bunx supermemory local` inside WSL (port 6767)
└── docs/
    ├── llm.md, docker.md, supermemory.md, web_search.md   # Original implementation specs/prompts
    ├── docs_supermemorylocal.md                           # Upstream Supermemory self-hosting docs
    ├── network.md                                         # Network-monitor usage notes
    ├── wireshark.md                                       # Wireshark capability reference (research)
    └── back.png, clawnet_updated.png                      # Images
```

**Import convention.** Every `core/*` module tries a flat import first (`from policy import …`, because the launcher puts `core/` on `sys.path`). If that fails, it falls back to `from core.policy import …`. This lets modules run as scripts, through the launcher, or as a package.

---

## 2. High-level architecture

```
                         ┌──────────────────────────── clawnet.py (launcher) ───────────────────────────┐
                         │  (no args) / --resolve / --auto → run_monitor   --copilot → run_copilot       │
                         │  --isolation → isolation.run_isolation_mode                                   │
                         │  run / clone / policy-init / install-interceptors / sandbox-list / -report    │
                         └───────────────┬───────────────────────────────────────────┬──────────────────┘
                                         │                                           │
                 ┌───────────── NETWORK MONITOR (core/clawnet.py) ──────┐   ┌──── SANDBOX (core/sandbox.py) ────┐
                 │ psutil.net_connections → policy.collect → Evidence    │   │ stage copy → ~/.clawnet/quarantine │
                 │                        → policy.evaluate → Verdict    │   │ docker run (hardened) + agent      │
                 │ Rich TUI • chat cmds • approval queue • Telegram      │   │ behavior.json → evaluate_behavior  │
                 └───────┬──────────────────────┬────────────────────────┘   │ SBOM • dep scan • sig • threat intel│
                         │                      │                            │ chain_of_trust → human → promote    │
                         ▼                      ▼                            └──────┬─────────────────────────────┘
               ┌───────────────┐      ┌──────────────────┐                          │
               │ policy.py     │◄─────┤ clawnet_agent.py │── llm.py ──► Ollama       │
               │ (decides)     │      │ (explains only)  │── replay.py (cassette)   │
               └──────┬────────┘      └────────┬─────────┘                          │
                      │ decisions.jsonl         │ reads                             │
                      ▼                         ▼                                   ▼
               ┌──────────────────────────────────────┐        ┌──────────────────────────────────┐
               │ memory.py  (evidence.jsonl)          │◄───────┤ web_search.py  (threat intel)    │
               │ append-only, fingerprints, lookups   │        │ Firecrawl → normalize → Supermem │
               └──────────────────────────────────────┘        │ Local + threat_cache.json        │
                                                               └──────────────────────────────────┘
                         telegram_alert.py: alerts + approve/deny of high-risk actions (both layers)
```

### Trust boundaries

| Boundary | What crosses it | How it's controlled |
|---|---|---|
| Policy engine → LLM | Sanitized JSON only (`policy.llm_payload`) | `scrub()` strips instruction-like text; `contradicts()` rejects explanations that disagree with the verdict |
| Host → container | A read-only copy of the target, the agent script, and a config file | `--cap-drop ALL`, `no-new-privileges`, resource limits, tmpfs, no Docker socket, env denylist and canaries |
| Container → host | `/clawnet-out/behavior.json` and logs | Scored on the host. The container holds no credentials. |
| Quarantine → host workspace | The vetted snapshot | Chain of trust, blocking steps, and human approval (`promotion_gate`) |
| Any high-risk action | kill / block / quarantine | `check_action` guardrails plus `needs_approval`. `--auto` does not bypass approval. |

---

## 3. Entry point: `clawnet.py` (root)

`main()` parses `sys.argv` by hand:

| Invocation | Target |
|---|---|
| `clawnet` (no args) | `core.clawnet.run_monitor(resolve=False, auto=False)` plus the public-IP fetch thread |
| `clawnet --resolve` / `--auto` | `run_monitor` with reverse DNS / auto mode. Auto mode still requires human approval. |
| `clawnet --copilot` | `run_copilot()`: a one-off network snapshot plus an LLM Q&A loop |
| `clawnet --isolation` | `isolation.run_isolation_mode()` |
| `clawnet run <path> [--cmd …] [--deep] [--offline]` | `SandboxRunner.run_target` → `promotion_gate`. Exits 1 if promotion is denied. |
| `clawnet clone <url> …` | `SandboxRunner.clone_and_run` → `promotion_gate` |
| `clawnet policy-init` | Writes or shows `~/.clawnet/sandbox_policy.json` |
| `clawnet install-interceptors` | Writes `git clone` wrapper helpers |
| `clawnet sandbox-list [N]` | Rich table built from `~/.clawnet/sandbox_runs.json` |
| `clawnet sandbox-report <run-id>` | JSON dump of the run metadata |

`--deep` skips the trusted-cache shortcut. `--offline` forces `network_mode=none`.

---

## 4. Module deep-dive

### 4.1 `core/policy.py`: deterministic policy engine (the only decider)

**Network evidence and rules**
- `Evidence` dataclass: pid, process, exe, SHA-256, trusted/suspicious/user-install path flags, parent process, proto, status, local/remote address, port, geo, memory history, and threat intelligence. `key()` gives a stable identity.
- `collect(conn, geo, memory, deep)` builds `Evidence` from a psutil connection. It hashes the executable, resolves the parent, queries memory for prior sightings, and runs threat-intel enrichment.
- `_rules(ev)` returns a list of `(rule, points, detail)` entries:
  - Drop-zone binary (`Temp`, `Downloads`, `Desktop`, …): +3. Also spawned by a shell: +2. Also talking to the internet: +2.
  - `DANGEROUS_PORTS` (23, 4444, 3389, 5900, 21, 1337, 31337): +3 or +4. `NOISY_PORTS` (22, 25, 3306, 5432, 6379, 27017): +2.
  - A foreign `SYN_SENT` (beacon pattern): +2. A live foreign connection, a listener on `0.0.0.0`, or an untrusted directory: +1 each.
  - Memory: a prior CRITICAL verdict adds +3, a prior SUSPICIOUS verdict adds +1. Threat-intel hits also add points.
  - Binaries under `AppData\Roaming` or `AppData\Local` count as user installs, not drop zones, which avoids false positives.
- `evaluate(ev) → Verdict(level, score, confidence, rules, action)`: `CRITICAL` at ≥ 6, `SUSPICIOUS` at ≥ 3, otherwise `SAFE`. `_recommend` picks the action.

**Sandbox behavior scoring**
- `evaluate_behavior(report)` scores `behavior.json` with `_behavior_rules` (`_BEHAVIOR_SIGNALS` and `_SENSITIVE_COST`). The bands are `DANGEROUS` ≥ 70 and `SUSPICIOUS` ≥ 35, capped at 100.
  - Main weights: canary exfiltrated +50, decoy credential read +45, reverse shell or miner +40, `curl|bash` +35, credential access +25–35, persistence +30, privilege escalation +30, install-time execution +25, foreign egress +10 per host, apt/apk install +15, package install +5.

**Guardrails**
- `check_action(action, pid, process, ip, path)` returns a refusal reason, or `""` if the action is allowed. It refuses:
  - killing `PROTECTED_PROCS` (explorer, lsass, …), PID ≤ 4, or ClawNet itself
  - blocking private or local IPs
  - quarantining System32/SysWOW64 files or anything outside the drop zones
- `needs_approval(action)`: `kill_process`, `block_ip`, `kill_and_block`, and `quarantine_file` always need approval.

**Prompt-injection firewall**
- `scrub(value)` removes instruction-like noise and truncates the value.
- `llm_payload(ev, v)` builds the only JSON the LLM ever sees. `_llm_threat_evidence` trims threat intel to structured fields.
- `contradicts(explanation, level)` uses regexes to catch "safe/benign" claims about non-SAFE verdicts and vice versa.

**Decision log**
- `log_decision`, `log_verdict`, and `read_decisions` append to or read `~/.clawnet/decisions.jsonl`, an immutable audit trail of verdicts, refusals, approvals, and promotions.
- `demo()` is a self-check, run by `python core/policy.py` and by pytest.

### 4.2 `core/clawnet_agent.py`: AI analyst

- `ClawNet` class. On startup it probes `llm.available()`, or treats replay mode as available.
- `request(key, ev, verdict)` publishes the policy verdict immediately as an `Analysis` whose reason is the rule summary. It logs the verdict, then queues an explanation job (queue size 30). The UI never waits on the LLM.
- A background `_worker` calls `_explain`: it builds `llm_payload`, adds `historical_evidence` from memory (read-only) and threat intel, and sends the result through `replay.transport(...)` → `llm.chat`. If the reply contradicts the verdict, the agent discards it and keeps the fallback.
- `copilot(question, context)` handles free-form Q&A over the network context, with a system prompt that treats all context as untrusted.
- The agent **never writes to memory.**

### 4.3 `core/llm.py`: LLM transport

- Uses only the stdlib (`urllib`) to call Ollama's native `POST {OLLAMA_HOST}/api/chat` endpoint.
- Settings: `OLLAMA_HOST` (default `http://localhost:11434`) and `OLLAMA_MODEL` (default `qwen3:8b`).
- `available()` is a 0.5 s TCP probe. `chat()` sends `temperature=0`, `think: False`, and `num_predict=max_tokens`, and strips any `<think>…</think>` blocks from the reply.
- It is the single point of LLM access for both the network agent and the sandbox explainer (`sandbox._ai_sandbox_explain`).

### 4.4 `core/memory.py`: forensic evidence store

- `SuperMemory`: an append-only store backed by `~/.clawnet/evidence.jsonl`. It keeps an in-memory deque of up to 10,000 records and migrates the legacy `memory.json` on first load.
- Writes: `store_evidence(record)` adds a behavior fingerprint and appends one line. `store_event` is a legacy adapter.
- Lookups (newest first): `lookup_sha256`, `lookup_process`, `lookup_ip`, `lookup_domain`, `lookup_repository`, `lookup_dependency`, `lookup_behavior(fingerprint|signals)`, `timeline`, `historical_context`, plus legacy helpers (`retrieve_events`, `risk_history_lookup`, `prior_decision_lookup`, `build_context`).
- `behavior_fingerprint(rec)` hashes behavior only: process tree shape, network behavior, accessed-file categories, install managers, and persistence. It ignores filenames and hashes, so **renamed malware still matches**.
- `make_evidence`, `make_event`, and `evidence_summary` are helpers for building records and producing the lines the agent cites.
- Note: the `backend` property always returns `"jsonl"`. Semantic search through the Supermemory server lives in `web_search.py`, not here, even though this module's docstring describes an optional mirror.

### 4.5 `core/web_search.py`: threat intelligence

- `DEFAULT_SOURCES`: CISA KEV (JSON feed), NVD, MITRE ATT&CK, GitHub Advisories, MSRC, Unit 42, Malwarebytes Labs, and Cisco Talos.
- `FirecrawlProvider`: scrapes a source when `FIRECRAWL_API_KEY` is set. `CrawlProvider` is a Protocol, so tests can inject a fake crawler.
- `normalize_document` uses regexes to extract structured evidence: CVE IDs, IPs, URLs, domains, hashes, CVSS, affected software, publication date, a summary (≤ 600 chars), and an IOC reputation. It never stores free-form LLM text.
- `ThreatIntelligenceService`:
  - `update()` crawls and stores documents in Supermemory Local (`supermemory` SDK, `SUPERMEMORY_API_URL` defaults to `http://localhost:6767`, timeout 5 s, 0 retries) and in the local cache `~/.clawnet/threat_cache.json` (TTL 6 h).
  - `search`, `enrich`, `enrich_many`, and `recent_cves` read that data. A **circuit breaker** (`_server_reachable`, a TCP probe with a cooldown) means a server that is down falls back to the cache instantly instead of stalling a verdict.
- `ThreatIntelligenceAgent` is a background refresher. Its interval comes from `THREAT_INTEL_INTERVAL_SECONDS` (default 6 h).
- Module-level helpers: `enrich_ip`, `enrich_domain`, `enrich_hash`, `enrich_url`, `enrich_package`, `enrich_observables`, `search_memory`, `get_recent_cves`, `get_related_threats`, `start_threat_intelligence_agent`, `stop_threat_intelligence_agent`.

### 4.6 `core/replay.py`: deterministic evaluation

- **Cassette** (`tests/recordings/clawnet.json`, or the path in `CLAWNET_CASSETTE`) is keyed by the SHA-256 of the payload content, not by call order.
- `CLAWNET_REPLAY=off|record|replay`. `transport(payload, live_call)` records or replays calls. An unrecorded call during replay raises `NotRecorded`, so the tool flags gaps instead of inventing answers.
- **Adversarial scoring:** `scenarios(ev)` mutates fixtures with prompt injections, and `HOSTILE_RESPONSES` simulates a lying or missing model. `score(fixtures)` gives a ship/no-ship result on three checks: decision determinism, guardrail safety, and explanation faithfulness.
- CLI: `python core/replay.py score`. The approach is borrowed from "Volo" as a technique only, with no dependency.

### 4.7 `core/clawnet.py`: network monitor TUI (host side)

- At import time it loads `.env` from the repo root and sets the Windows console to UTF-8.
- **State:** `ClawState` holds the connections, new-connection keys, chat history, a lock, and the pending approvals.
- **System info:** VPN detection by interface-name scan, WiFi SSID via `netsh`, gateway and DNS via `ipconfig`, public IP from `api.ipify.org` (cached 60 s), GeoIP (cached), and byte counters.
- **Scoring hot path:** `verdict_for(conn)` is the only place a network risk level is decided. It calls `policy.collect` and `policy.evaluate` and caches the result for 5 s per connection key. `_persist_verdict` writes verdicts into memory.
- **Threads:**
  - `_data_collector`: runs once per second. It lists connections, runs analysis and approvals, and sends Telegram alerts.
  - `_input_thread`: key handling (`T` for chat, `j`/`k` to scroll).
  - `_chat_worker`: processes chat commands.
  - `_fetch_public_ip`: fetches the public IP in the background.
- **Rendering:** `rich.Live` at 2 fps draws the banner, header, connections table (FLAGS/RISK/PROTO/STATUS/LOCAL/REMOTE/COUNTRY/PORT/PROCESS/PID, with new rows highlighted for 6 s), stats, the ClawNet AI panel, and the chat panel.
- **Chat commands** (`parse_command` / `_run_chat_command`): `explain <pid>`, `kill <pid>`, `block <ip>`, `suspend <pid>`, `quarantine <path>`, `close port <n>`, `show foreign`, `show high`. Anything else goes to the copilot.
- **Actions** (`execute_action`):
  - `kill_process` / `suspend_process` use psutil.
  - `block_ip` adds a Windows firewall rule through `netsh advfirewall`.
  - `close_port` kills the listeners on that port.
  - `quarantine_file` uses `send2trash`.
  - All of these go through `policy.check_action` and approval first.
- **Approval:** `_maybe_request_approval` queues a remediation for CRITICAL verdicts. The approval happens in Telegram if it's configured, or in the log with the exact command to type.
- `run_copilot()` takes a 3 s snapshot and then runs a prompt loop. It shows Ollama setup hints if the model is unavailable.

### 4.8 `core/sandbox.py`: isolation runtime

**`SandboxRunner.run_target(path, runtime_command, deep_scan, force_network_mode, stream)`**, step by step:
1. **Check prerequisites.** Docker must be on PATH. Create the run id `sbx-<epoch>` and a temp output directory (`stdout.log`, `stderr.log`, `metadata.json`, and others).
2. **Load the policy** from `~/.clawnet/sandbox_policy.json`, merged over `_DEFAULT_POLICY`.
3. **Trusted-cache shortcut.** If the file-content fingerprint of the original source matches a previous SAFE and approved run (and `--deep` isn't set), return SAFE without running anything.
4. **Quarantine.** `_stage_to_quarantine` copies the source to `~/.clawnet/quarantine/<id>/`. The working tree is never mounted.
5. **Canary.** Generate a per-run `clawnet-canary-<hex>`. `_write_agent_config` writes the canary and the target name for the in-container agent.
6. **Build the hardened `docker run`** (`_build_agent_docker_cmd`, through the `_BACKENDS` registry):
   - `--cpus`, `--memory`, `--memory-swap` (equal to memory), `--pids-limit`, and `nofile`/`core` ulimits
   - `--cap-drop ALL`, `--security-opt no-new-privileges`, and optional seccomp/AppArmor profiles, `--read-only`, and `--runtime` (gVisor `runsc` or Kata)
   - tmpfs mounts for `/tmp`, `/run`, and `/var/tmp`. The workspace is mounted `:ro`, the output directory `:rw`, and the agent and config `:ro`.
   - Env vars on the denylist are blanked, and the names in `canary_env_keys` get the canary value.
   - Image `python:3.11-slim` (`--pull missing`) runs `python /clawnet-agent/agent.py "<cmd>"`.
   - The start command comes from `_detect_start_command`, based on files such as `package.json` and `main.py`.
7. **Run.** In streaming mode, `_run_container_live` and `_SandboxLiveView` show a live Rich view with stages, a running score, signals, and egress. `_poll_net` samples the container network.
8. **Score.**
   - Read `behavior.json`, the primary evidence. `net-sample.log` (`/proc/net`) is a fallback.
   - `policy.evaluate_behavior(behavior)` scores it. Output heuristics (`_SUSPICIOUS_PATTERNS` via `_heuristic_risk`) can raise the score but never lower it.
   - `_build_sbom` compares declared packages with those installed at runtime. `_scan_dependencies` checks `_BAD_PACKAGES`, typosquats, and undeclared installs.
   - `enrich_observables(ips=…, packages=…)` adds threat intel. `_verify_signature` checks whether the git HEAD commit is signed.
   - Reputation memory and behavioral memory (a fingerprint match under any name) carry earlier verdicts forward.
9. **Explain and persist.** `_ai_sandbox_explain` calls the LLM with sanitized data. The run is logged with `log_decision`, stored with `_store_memory` (evidence), and indexed with `_index_run` in `sandbox_runs.json`. `_maybe_telegram_alert` sends an alert, and `_print_report` prints the report.

**`chain_of_trust(result)`** returns steps of the form `{step, ok, blocking, detail}`:

| Step | Blocking? |
|---|---|
| Behavior Report | no (warns if no telemetry) |
| Policy Engine (not DANGEROUS) | **yes** |
| Signature Verification | only if `require_signature` |
| SBOM | no (informational) |
| Dependency Scan (no known-malicious) | **yes** |
| Threat Intelligence (no IOC hits) | **yes** |

**`promotion_gate(result)`:** any failed blocking step means the target stays in quarantine and the human cannot override it. Otherwise, `_human_approval` asks for approval, through Telegram if `CLAWNET_TELEGRAM_APPROVAL=1` or at a console prompt, with a default of Y for SAFE and N otherwise. `promote_to_host` then copies the vetted snapshot to `$CLAWNET_HOST_WORKSPACE/<name>/` (default `~/clawnet-workspace`). Reputation and the decision log are updated either way.

Other methods: `clone_and_run` (git clone, then `run_target`), `ensure_policy_file`, `install_interceptors`, `list_runs`, `load_report`, and `_fingerprint_target` (hashes at most 300 files of at most 512 KB each).

### 4.9 `core/container_agent.py`: in-container supervisor

This is the only ClawNet code that runs inside the container. It uses only the stdlib and works on Python 3.8+.
- It runs the target command with `subprocess.Popen(shell=True)`, mirrors its output, and scans each line (`_scan_output_line`).
- **Decoys:** `_plant_decoys(canary)` writes fake credential files (SSH, AWS, wallets, and similar) that contain the canary.
- `_net_monitor`: parses `/proc/net/tcp*` and `/proc/net/udp*` to find foreign egress.
- `_behavior_monitor`: polls `/proc` once per second to collect:
  - the process tree and full ancestry chains (`sh > npm > node > curl`)
  - package installs (`_PKG_MANAGERS`) and install-time execution (`_INSTALL_EXEC`)
  - sensitive files opened, via `/proc/<pid>/fd`
  - persistence file mtime changes (cron, systemd, rc.local, profiles, `ld.so.preload`)
  - privilege-escalation commands (`_ESCALATION`)
  - command signals (`_CMD_SIGNALS`)
  - the canary appearing in command lines or egress
- At the end it writes `/clawnet-out/behavior.json` (snapshot, duration, exit code). Alerts go to a log. **The container never sends alerts itself.**

### 4.10 `core/isolation.py`: sandbox TUI

`run_isolation_mode()` shows a banner and a menu with these options: clone and sandbox a GitHub repo, sandbox a local path, and view run history. It streams the live container view, shows a verdict panel colored by level, then runs `promotion_gate`.

### 4.11 `core/telegram_alert.py`: alerts and remote approval

- `TelegramAlert` calls the Bot HTTP API with urllib only. Methods: `send_alert`, `send_clawnet_alert` (formatted verdict), `start_polling` / `get_updates` / `_process_update` (approve or deny replies), `add_pending(PendingAction)`, the `set_execute_callback` hook, and `send_reply`. `_persist_chat_id` saves a chat id it discovers.
- `TelegramMock` generates weighted fake alerts (LOW 70 %, MED 20 %, HIGH 10 %) for testing. It is controlled by `TELEGRAM_MOCK_ENABLED`. Note: when this variable is unset, the code in `run_monitor` defaults it to on (`"1"`). `.env.example` sets it to `0`.

### 4.12 `core/netwatch.py`: legacy

NETWATCH v1.0 is the original standalone monitor, with a simple port-table risk score and no policy engine or AI. It is kept for reference and is not used by the launcher.

---

## 5. Data flows

### 5.1 Network connection → verdict → explanation → action
```
psutil.net_connections()
  → policy.collect(conn, geo, memory)     # exe, sha256, parent, geo, memory history, threat intel
  → policy.evaluate(ev) → Verdict         # rules + score + confidence + action
  → table row / flags (instant)
  → ClawNet.request(...)                  # publish verdict; log_verdict → decisions.jsonl
       └─ worker: llm_payload → replay.transport → llm.chat → contradicts()? discard : keep
  → _persist_verdict → memory.store_evidence (deterministic source only)
  → CRITICAL? → check_action → needs_approval → Telegram / console approval → execute_action
```

### 5.2 Unknown project → host
```
source → fingerprint → (trusted cache hit? → SAFE)
       → copy to ~/.clawnet/quarantine/<id>
       → hardened docker run + container_agent (decoys, canary, /proc telemetry)
       → behavior.json → policy.evaluate_behavior (+ output heuristics, raise-only)
       → SBOM + dependency scan + signature + threat-intel enrichment + memory fingerprints
       → AI explanation (sanitized) → decision log + evidence memory + runs index
       → chain_of_trust → blocking failures stop here
       → human approval → copy snapshot to $CLAWNET_HOST_WORKSPACE/<name>
```

---

## 6. On-disk state (`~/.clawnet/`)

| File | Owner | Purpose |
|---|---|---|
| `decisions.jsonl` | policy.py | Immutable audit log of verdicts, refusals, approvals, and promotions |
| `evidence.jsonl` | memory.py | Append-only forensic evidence (source of truth) |
| `memory.json` | memory.py | Legacy file, migrated on first load |
| `threat_cache.json` | web_search.py | Local cache of crawled threat intel |
| `sandbox_policy.json` | sandbox.py | User-editable sandbox policy |
| `sandbox_reputation.json` | sandbox.py | Per-target fingerprint, verdict, and approval |
| `sandbox_runs.json` | sandbox.py | Index of runs used by `sandbox-list` |
| `quarantine/<id>/` | sandbox.py | Staged copies of targets |

Per-run output lives in a temporary `clawnet-sbx-<ts>-*` directory: `stdout.log`, `stderr.log`, `behavior.json`, `metadata.json`, `agent-config.json`, and the sample logs.

---

## 7. Configuration (`.env`, all optional)

| Variable | Used by | Default / meaning |
|---|---|---|
| `OLLAMA_HOST`, `OLLAMA_MODEL` | llm.py | `http://localhost:11434`, `qwen3:8b` |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | telegram_alert, clawnet, sandbox | Enable alerts |
| `CLAWNET_TELEGRAM_APPROVAL` | sandbox | Send promotion approvals to Telegram |
| `TELEGRAM_MOCK_ENABLED` | clawnet | Fake alert generator |
| `FIRECRAWL_API_KEY` | web_search | Enables crawling |
| `THREAT_INTEL_INTERVAL_SECONDS` | web_search | Refresh interval (21600) |
| `CLAWNET_THREAT_CACHE_PATH`, `CLAWNET_THREAT_CACHE_TTL_SECONDS` | web_search | Cache location and TTL |
| `SUPERMEMORY_API_KEY`, `SUPERMEMORY_API_URL` | web_search | Supermemory Local (`:6767`) |
| `CLAWNET_HOST_WORKSPACE` | sandbox | Promotion destination (`~/clawnet-workspace`) |
| `CLAWNET_REPLAY`, `CLAWNET_CASSETTE` | replay | `off`/`record`/`replay`; cassette path |

If none of these are set, the policy engine, sandbox, memory, and decision log still work fully offline.

**Sandbox policy keys** (`_DEFAULT_POLICY`):
- `max_runtime_seconds` 300, `cpu_limit` 1.5, `memory_limit` 1536m, `pids_limit` 256
- `network_mode` bridge or none, `read_only_workspace`, `read_only_rootfs`
- `enable_telemetry`, `telemetry_interval_seconds`, `block_on_foreign_egress`, `foreign_egress_risk_bonus`
- `backend`, `runtime`, `seccomp_profile`, `apparmor_profile`, `no_swap`
- `plant_decoy_credentials`, `require_signature`, `deny_env_keys`, `canary_env_keys`

---

## 8. Testing

| Command | What it checks |
|---|---|
| `python core/policy.py` | Rules, guardrails, and the injection firewall (`demo()`) |
| `python core/memory.py` | Evidence store, reload, and fingerprinting (`demo()`) |
| `python core/replay.py score` | Offline ship/no-ship evaluation against the cassette |
| `python -m pytest tests/` | See below |
| `python tests/sandbox_demo.py [--keep]` | Real Docker end-to-end run with a harmless but suspicious repo (pip install, child processes, HTTP, env reads, `~/.ssh` access, a shell) |

`python -m pytest tests/` runs these tests:
- `test_policy_rules_and_guardrails`
- `test_deterministic_replay_ships`
- `test_unrecorded_call_flags_never_fabricates`
- `test_llm_cannot_change_the_verdict`
- `test_high_risk_actions_need_approval`
- `test_threat_intelligence_uses_structured_supermemory_evidence` (fake Supermemory client)

Everything except `sandbox_demo.py` runs offline without API keys, network access, or Docker.

---

## 9. External integrations

| Integration | How | Required? |
|---|---|---|
| Docker | Called through the `docker` CLI | Sandbox only |
| Ollama (`qwen3:8b`) | HTTP `/api/chat` | No. Explanations fall back to rule summaries. |
| Supermemory Local | `supermemory` SDK → `localhost:6767`. On Windows it runs in WSL through `scripts/supermemory-local.sh` (bun, `bunx supermemory local`). | No |
| Firecrawl | REST scrape | No |
| Telegram Bot API | urllib HTTP | No |
| ip-api / ipify | GeoIP and public IP lookups | No (the UI shows `?`) |
| Windows tools | `netsh`, `ipconfig`, `netsh advfirewall` | Host monitor and actions (Windows-first) |

---

## 10. Inconsistencies and notes found while reading

- **README is behind the latest commit.** The README still says explanations use "GPT-4o-mini" and asks for `OPENAI_API_KEY`. The code (`llm.py`) and `.env.example` now use local Ollama `qwen3:8b` with no API key.
- `scripts/supermemory-local.sh` still forwards `OPENAI_API_KEY` into WSL, because the Supermemory server needs an LLM key on first boot.
- The `memory.py` docstring describes an optional Supermemory mirror, but `SuperMemory.backend` is always `"jsonl"`. Only `web_search.py` talks to the Supermemory server.
- `TELEGRAM_MOCK_ENABLED` defaults to on in the code when the variable is unset, but `.env.example` sets it to off.
- `pyproject.toml` requires Python ≥ 3.10, while the README says 3.11+. `supermemory` is an optional extra in `pyproject.toml` but a hard requirement in `core/requirements.txt`.
- `core/clawnet.py` still calls itself "ClawNet v2" in its docstring, while the package version is 3.0.0.
- `docs/llm.md`, `docker.md`, `supermemory.md`, and `web_search.md` are the original implementation specs (prompts), not user documentation.
- `core/netwatch.py` is dead code as far as the launcher is concerned.
