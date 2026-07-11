<h1 align="center">ClawNet</h1>

<p align="center">
  <img width="920" height="171" alt="ClawNet" src="https://github.com/user-attachments/assets/62e1cdf7-c5de-4e5e-8d59-3cabaadc676c" />
</p>

<p align="center">
  <b>AI-powered runtime defense for hosts, containers, and Kubernetes.</b>
</p>

---

ClawNet is an AI-powered terminal security platform with three core defense layers:

- **Live host network monitoring**
- **Isolation sandbox for unknown code**
- **Autonomous Kubernetes incident response**

It watches your machine in real time, sandboxes suspicious projects before they touch the host, and can autonomously investigate production Kubernetes failures using specialized AI agents.

> "Nothing runs on the host before ClawNet approves it."

---

# Modes

| Mode | Command | What it does |
|---|---|---|
| Network Monitor | `clawnet` | Live TUI watching all TCP/UDP connections on your host |
| Copilot | `clawnet --copilot` | AI chat interface for your current network state |
| Isolation Sandbox | `clawnet --isolation` | Interactive TUI: clone/run anything in Docker, monitored from inside |
| Run local project | `clawnet run <path>` | Sandbox a local folder in Docker |
| Clone + run | `clawnet clone <url>` | Clone a GitHub repo and sandbox it immediately |
| View past runs | `clawnet sandbox-list` | Table of recent sandbox verdicts |
| Full report | `clawnet sandbox-report <run-id>` | JSON dump of a past sandbox run |
| Policy setup | `clawnet policy-init` | Create/view the sandbox policy file |
| Git interceptors | `clawnet install-interceptors` | Install wrappers that route `git clone` through ClawNet |
| Kubernetes Defense | `clawnet k8s-watch` | Autonomous Kubernetes monitoring + remediation |

---

# Features

---

## Network Monitor (host-side)

- Live TCP/UDP connection monitoring with 1-second refresh
- Real-time process tracking with path validation
- GeoIP lookup for remote IPs
- VPN status detection
- Automatic risk scoring (LOW / MED / HIGH)
- OpenClaw AI-powered threat analysis per connection
- Natural language security explanations
- Kill process / block IP recommendations
- Telegram alerts for HIGH and CRITICAL detections
- Persistent threat memory (local JSON + optional Supermemory cloud)

---

## Isolation Sandbox

- Every unknown project runs inside a locked-down Docker container
- **ClawNet agent runs inside the container** — monitors the app from within
- Polls `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` every second
- Fires a **Telegram ping instantly** when a new foreign IP is detected
- Scans stdout/stderr lines in real time for suspicious patterns
- Sends Telegram alerts when risk crosses SUSPICIOUS or DANGEROUS thresholds
- Workspace mounted read-only by default
- Security hardening:
  - `--cap-drop ALL`
  - `--security-opt no-new-privileges`
  - PID / memory / CPU limits
- Sensitive host env vars are blanked inside containers
- AI verdict generation via GPT-4o-mini
- Reputation cache for trusted projects
- Promotion gate:
  - SAFE → auto allow
  - SUSPICIOUS → approval required
  - DANGEROUS → auto blocked
- Live Rich TUI with streaming output and risk telemetry

---

## Kubernetes Runtime Defense

ClawNet extends into Kubernetes — an autonomous AI incident-response layer for production clusters.

Instead of only detecting threats, ClawNet can now:
- Investigate failures
- Diagnose root causes
- Plan remediations
- Execute safe fixes
- Route dangerous actions through human approval

> "When production breaks at 3am, ClawNet shouldn't just alert you — it should investigate, explain, and respond."

### Multi-Agent System

```text
                    +----------------------+
                    |  INCIDENT COMMANDER  |
                    |     (Supervisor)     |
                    +----------+-----------+
                               |
            +------------------+------------------+
            |                  |                  |
   +--------v--------+ +------v------+ +---------v---------+
   |   SCOUT AGENT   | |DOCTOR AGENT | |  EXECUTOR AGENT   |
   | Cluster watcher | | Root cause  | | Safe remediation  |
   +-----------------+ +-------------+ +-------------------+
````

### 7-Stage Incident Pipeline

1. Observe — Poll cluster state continuously
2. Detect — AI classifies anomalies
3. Diagnose — Analyze logs/events/metrics
4. Plan — Generate remediation plan
5. Safety Gate — Approval routing
6. Execute — Safe kubectl action
7. Explain & Log — Audit trail + summaries

### Kubernetes Features

* Autonomous anomaly detection
* Root-cause analysis from logs/events/metrics
* Predictive alerts (OOM detection before crash)
* Self-evolving runbook memory
* Human-in-the-loop approvals via Slack
* RBAC-scoped least-privilege execution
* Natural language war-room interface
* Chaos engineering mode
* Blockchain-backed audit trail

### Supported Incident Types

| Incident           | Severity | Auto-Fix |
| ------------------ | -------- | -------- |
| CrashLoopBackOff   | HIGH     | Yes      |
| OOMKilled          | HIGH     | Yes      |
| Evicted Pod        | LOW      | Yes      |
| Pending Pod        | MED      | HITL     |
| ImagePullBackOff   | MED      | HITL     |
| CPU Throttling     | MED      | HITL     |
| Deployment Stalled | HIGH     | HITL     |
| Node NotReady      | CRITICAL | HITL     |

---

# Detection Patterns (inside container)

| Pattern                         | Signal                     | Risk Points |
| ------------------------------- | -------------------------- | ----------- |
| `xmrig`, `stratum+tcp`          | Cryptominer behavior       | +35         |
| `nc -e`, `netcat -l`            | Reverse shell / listener   | +35         |
| `curl ... \| bash`              | Remote code execution pipe | +30         |
| `private key`, `seed phrase`    | Wallet key material        | +30         |
| Foreign egress IP               | Outbound to non-private IP | +30         |
| `.ssh`, `id_rsa`, `known_hosts` | SSH material access        | +25         |
| `curl ... pastebin/ngrok`       | Exfiltration endpoint      | +25         |
| `ufw disable`, `iptables off`   | Firewall tampering         | +25         |
| `ssh-keyscan`, `ssh-copy-id`    | SSH key distribution       | +25         |
| `adduser`, `sudoers`            | Privilege persistence      | +20         |
| `crontab`                       | Cron job modification      | +20         |
| `/proc/<pid>/environ`           | Process env read           | +20         |
| `base64 -d`, `powershell -enc`  | Obfuscated execution       | +20         |
| `systemctl enable`              | Service persistence        | +20         |
| `apt-get install`               | System package install     | +15         |
| `printenv`                      | Env var enumeration        | +15         |
| `chmod 777`                     | Broad permission grant     | +12         |
| `pip install`, `npm install`    | Package installation       | +8          |

---

# Tech Stack

## Core Runtime Monitoring

* Python 3.11+
* psutil
* subprocess
* socket

## Isolation Sandbox

* Docker CLI
* `container_agent.py`

## Kubernetes Runtime Defense

* LangGraph
* FastMCP
* kubectl tools
* FastAPI
* Slack Block Kit
* LiteLLM
* Claude Opus / Sonnet

## AI Layer

* OpenClaw
* GPT-4o-mini
* Claude models

## Memory

* Local JSON
* Optional Supermemory backend

## UI

* Rich TUI
* React + Tailwind dashboard

## Audit Layer

* Stellar Soroban smart contracts

---

# Installation

## Clone Repository

```bash
git clone https://github.com/rajarshidattapy/clawnet.git
cd clawnet
```

---

## Setup Virtual Environment

```bash
python -m venv venv
source venv/bin/activate

# Windows
venv\Scripts\activate
```

---

## Install Dependencies

```bash
pip install -r core/requirements.txt
```

---

# Environment Variables

Create a `.env` file in the repo root:

```env
# OpenAI
OPENAI_API_KEY=your_openai_key

# Telegram alerts
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Optional memory backend
SUPERMEMORY_API_KEY=your_supermemory_key

# Slack approval system
SLACK_BOT_TOKEN=your_slack_bot_token
SLACK_SIGNING_SECRET=your_slack_signing_secret

# Optional Telegram HITL approvals
CLAWNET_TELEGRAM_APPROVAL=1
```

---

# Telegram Chat ID

1. Message your bot once
2. Run:

```bash
curl https://api.telegram.org/bot<TOKEN>/getUpdates
```

3. Copy the `chat.id`

---

# Prerequisites

## Docker

```bash
docker --version
docker ps
```

ClawNet automatically pulls:

```bash
python:3.11-slim
```

---

## Kubernetes (optional)

For Kubernetes runtime defense:

```bash
kubectl cluster-info
minikube status
```

---

# Run ClawNet

---

## Network Monitor

```bash
python clawnet.py
# or
clawnet
```

### Keyboard Shortcuts

| Key       | Action       |
| --------- | ------------ |
| `j` / `k` | Scroll       |
| `c`       | Open copilot |
| `q`       | Quit         |

---

## Isolation Mode

```bash
clawnet --isolation
```

Interactive menu:

```text
[1] Sandbox GitHub repo
[2] Sandbox local project
[3] View run history
[4] Manage policy file
[Q] Quit
```

---

## Clone + Sandbox

```bash
clawnet clone https://github.com/someone/project.git

clawnet clone https://github.com/someone/project.git --deep

clawnet clone https://github.com/someone/project.git --offline

clawnet clone https://github.com/someone/project.git --cmd "python main.py"
```

---

## Sandbox Local Project

```bash
clawnet run ./my-project

clawnet run ./my-project --deep

clawnet run ./my-project --offline
```

---

## Kubernetes Defense

```bash
clawnet k8s-watch
```

Example actions:

* Investigate pod crashes
* Explain root causes
* Rollback deployments
* Detect resource exhaustion
* Route risky actions to Slack approval

---

## Sandbox Reports

```bash
clawnet sandbox-list

clawnet sandbox-list 50

clawnet sandbox-report sbx-1748123456
```

---

# Telegram Alert Flow

```text
Container starts
        ↓
"Sandbox Started" alert
        ↓
[real-time]
Foreign IP detected
        ↓
Suspicious output detected
        ↓
Risk score updated
        ↓
Container exits
        ↓
AI verdict generated
        ↓
SAFE / SUSPICIOUS / DANGEROUS
```

---

# Kubernetes Incident Flow

```text
Cluster anomaly detected
        ↓
AI agents investigate
        ↓
Root cause generated
        ↓
Remediation plan proposed
        ↓
Safety gate triggered
        ↓
Auto-fix OR approval request
        ↓
Verification loop
        ↓
Incident audit logged
```

---

# Sandbox Policy

```bash
clawnet policy-init
```

Example policy:

```json
{
  "max_runtime_seconds": 300,
  "cpu_limit": "1.5",
  "memory_limit": "1536m",
  "pids_limit": 256,
  "network_mode": "bridge",
  "read_only_workspace": true,
  "enable_telemetry": true,
  "telemetry_interval_seconds": 2,
  "block_on_foreign_egress": true,
  "foreign_egress_risk_bonus": 30,
  "deny_env_keys": [
    "OPENAI_API_KEY",
    "SUPERMEMORY_API_KEY",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN"
  ]
}
```

---

# Risk Levels

| Score  | Level      | Outcome           |
| ------ | ---------- | ----------------- |
| 0–34   | SAFE       | Auto allowed      |
| 35–69  | SUSPICIOUS | Approval required |
| 70–100 | DANGEROUS  | Auto blocked      |

---

# Project Structure

```bash
clawnet/
│
├── core/
│   ├── clawnet.py
│   ├── sandbox.py
│   ├── container_agent.py
│   ├── isolation.py
│   ├── openclaw.py
│   ├── telegram_alert.py
│   ├── memory.py
│   ├── netwatch.py
│   └── requirements.txt
│
├── k8s/
│   ├── agents/
│   ├── graph/
│   ├── mcp_server/
│   ├── prediction/
│   ├── slack/
│   ├── api/
│   ├── blockchain/
│   └── chaos/
│
├── docs/
│   ├── README.md
│   └── dockerized_runtime.md
│
├── frontend/
│
├── contracts/
│
├── clawnet.py
├── pyproject.toml
└── .env
```

---

# Security Model

ClawNet follows a layered runtime-defense model:

1. Detect suspicious behavior
2. Isolate unknown code
3. Monitor from inside the runtime
4. Analyze behavior using AI
5. Gate dangerous actions
6. Require approval for risky operations
7. Explain every decision transparently

---

# Vision

ClawNet is evolving into a full autonomous runtime defense system.

Not just:

> "What is happening?"

But:

> "What caused it, how dangerous is it, and should the system act automatically?"

ClawNet aims to become an AI-native security layer for:

* Local machines
* Containers
* CI/CD pipelines
* Kubernetes clusters
* Autonomous infrastructure

Where every runtime is continuously monitored, explainable, and policy-gated before it can impact production.

---

# Future Scope

* eBPF runtime instrumentation
* Multi-cluster Kubernetes monitoring
* Autonomous GitHub remediation PRs
* Threat graph visualization
* Distributed sandbox fleet
* WASM sandbox runtime
* AI-generated permanent fixes
* Cost optimization recommendations
* Incident correlation engine
* Cloud-native runtime firewall

---

# License

MIT License

---

# Disclaimer

ClawNet is a defensive security platform intended for:

* malware analysis
* runtime inspection
* infrastructure protection
* incident response
* safe execution of untrusted code

Users are responsible for complying with local laws and organizational security policies.

```
```
