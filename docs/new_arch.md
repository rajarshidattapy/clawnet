# ClawForge

> **Turn ClawNet from a security terminal into an agentic harness.**

## 1. Goal

ClawForge extends the existing ClawNet terminal with **TrueForge-powered agent orchestration**.

It does **not** replace ClawNet or create a separate execution environment.

The existing ClawNet capabilities become primitives that an internal agentic system can safely use.

---

## 2. Architecture

```text
                         CLAWFORGE
              Agentic Harness  ·  console + /watch
                           │
                           ▼
                  ┌─────────────────┐
                  │  Internal Agent │   clawforge agent (OpenAI model)
                  │     System      │
                  └────────┬────────┘
                           │
                      ┌────▼────┐
                      │TrueForge│   sessions · subagents · tool orchestration
                      │         │   approval checkpoints · execution state
                      └────┬────┘
                           │  MCP (streamable HTTP, bearer token, localhost only)
                           ▼
                  ┌─────────────────┐
                  │ ClawForge MCP   │   21 tools, annotated observe / execute / control
                  │     server      │
                  └────────┬────────┘
                           ▼
                    ┌─────────────┐
                    │   ClawNet   │
                    │     Core    │
                    └──────┬──────┘
                           │
     ┌─────────────┬───────┼────────────┬──────────────────┐
     ▼             ▼       ▼            ▼                  ▼
  Network       Policy   Sandbox     Evidence         Threat intel
  Monitor       Engine   Runtime     Memory           (Firecrawl →
  (psutil)     (decides) Daytona ▸   (JSONL)           Supermemory)
                         Docker
     │             │       │            │                  │
     └─────────────┴───────┼────────────┴──────────────────┘
                           ▼
                       Host/System
```

---

## 3. Core Principle

The agent **never directly controls the system**.

Every operation follows:

```text
Agent
  ↓
TrueForge Harness
  ↓
ClawNet Capability
  ↓
Policy / Security Checks
  ↓
Execution
  ↓
Evidence
  ↓
Agent
```

For irreversible operations:

```text
Agent
  ↓
Propose Action          (preview_action: guardrail, blast radius, reversibility)
  ↓
Policy Check
  ↓
APPROVAL REQUIRED       (TrueForge pauses; the harness re-measures and briefs the human)
  ↓
Human
  ├── Approve → Execute (ClawNet guardrails run again and can still refuse)
  └── Reject  → Stop    (agent is told not to retry or work around it)
```

---

## 4. ClawNet Capabilities

Existing ClawNet functionality becomes agent-accessible capabilities. The tier decides the gate:

| Tier | Tools | Gate |
|---|---|---|
| **Observe** (read-only) | `system_status`, `list_connections`, `suspicious_processes`, `inspect_process`, `who_is_listening`, `explain_pid`, `lookup_evidence`, `threat_intel`, `recent_decisions`, `preview_action`, `list_sandbox_runs`, `sandbox_report` | runs autonomously |
| **Execute** (sandbox) | `sandbox_run_code`, `sandbox_run_path`, `sandbox_clone` | runs autonomously in an isolated, disposable sandbox |
| **Control** (changes the host) | `kill_process`, `suspend_process`, `block_ip`, `quarantine_file`, `close_port`, `promote_sandbox_run` | **human approval on every call** |

The existing security primitives remain authoritative, and the agent cannot override them:
- Protected processes, private IPs and System32 files are refused even after approval.
- A failed blocking chain-of-trust step refuses promotion whoever approved it.
- Everything the machine or a sandbox returns is scrubbed by ClawNet's prompt-injection firewall before the model sees it.

---

## 5. TrueForge Responsibilities

TrueForge provides the agentic infrastructure:

- Agent lifecycle
- Tool orchestration
- Sessions
- Subagents
- Approval checkpoints
- Execution state

ClawForge connects these primitives to ClawNet through an MCP server. TrueForge's own sandbox (Daytona via TrueForge) is turned off in the agent spec, because ClawNet runs its own sandbox with behavioural telemetry.

---

## 6. State Model

```text
PLANNING
   ↓
EXECUTING / OBSERVING
   ↓
ANALYZING
   ↓
   ├── CONTINUE ──────→ EXECUTING / OBSERVING
   │
   └── APPROVAL
          ↓
      APPROVED → EXECUTE → ANALYZING
          │
      REJECTED → STOP
   ↓
DONE
```

The **harness owns the state machine**, not the model. `HarnessState` changes state on TrueForge events (a tool call's tier, a tool response, an approval request), never on model text. The transitions are fixed, and any illegal one is reported.

---

## 7. Architecture Goal

Transform:

```text
Human
  ↓
ClawNet Terminal
  ↓
System
```

into:

```text
Human
  ↓
ClawForge
  ↓
Internal Agentic System
  ↓
TrueForge
  ↓
ClawNet
  ↓
System
```

**ClawForge is ClawNet evolving from a terminal that humans operate into a harness through which agents can safely operate.**

TrueForge is MIT-licensed and runs locally (Node.js 22.14+). Links: [GitHub](https://github.com/truefoundry/trueforge) · [npm](https://www.npmjs.com/package/@truefoundry/trueforge) · [docs](https://trueforge.dev).

---

## 8. Implementation map

| Architecture piece | Where it lives |
|---|---|
| Internal agent system | `clawforge` agent spec in `clawforge/harness.py`. It runs in TrueForge on an OpenAI model (`CLAWFORGE_MODEL`, default `gpt-5.4-mini`). |
| TrueForge: sessions, subagents, approval | `python -m clawforge setup` registers the OpenAI provider, the `clawnet` MCP connector and the agent. `run`, the console and `/watch` drive sessions. |
| ClawNet capabilities | `clawforge/capabilities.py`, exposed as MCP tools by `clawforge/mcp_server.py` |
| Policy / security checks | `core/policy.py` guardrails, re-checked after every approval |
| Approval required → Human | Control tools carry `destructiveHint` and are also named in `require_approval_for_tools`. The approval briefing is re-measured locally by `preview_action`. |
| Sandbox runtime | `core/sandbox.py`: **Daytona** is primary (`_run_daytona`) and **Docker** is the fallback, with the same telemetry agent (`core/container_agent.py`) in both |
| Evidence | `~/.clawnet/decisions.jsonl` (decision log) and `~/.clawnet/evidence.jsonl` (forensic memory) |
| Threat intel / news | `core/web_search.py`: Firecrawl crawl → structured evidence → Supermemory Local, plus the local cache `~/.clawnet/threat_cache.json` |
| State model (§6) | `HarnessState` in `clawforge/harness.py` |
| Operator UI | `clawforge/tui.py` (console, status, `/news`) and `clawforge/dashboard.py` (`/watch`) |

---

## 9. Sandbox: Daytona primary, Docker fallback

```text
target (path / git URL / agent-written code)
  → copy into ~/.clawnet/quarantine/<run>        (your working tree is never touched)
  → backend = CLAWNET_SANDBOX_BACKEND or (DAYTONA_API_KEY ? daytona : docker)
      Daytona: ephemeral sandbox · upload copy + telemetry agent · process.exec · download behavior.json · delete
      Docker : docker run --rm, cap-drop ALL, no-new-privileges, limits, read-only workspace
      (Daytona error → falls back to Docker if it is running)
  → policy engine scores behavior.json → chain of trust → verdict
  → promotion to the host only via promote_sandbox_run (human-approved)
```

- **Start command:** if you don't give one, it's detected: a manifest (`requirements.txt`, `pyproject.toml`, `package.json`), else a conventional entry (`main.py`, `app.py`, `index.js`, …), else the only script present.
- **Runs that prove nothing:** if nothing ran, or the code crashed on a missing module, the verdict is **INCONCLUSIVE**, never SAFE. The agent re-runs it with an explicit command.
- **Secrets inside the sandbox:** host env vars are never forwarded. Denied keys are blanked, and canary keys get a per-run canary value, alongside the decoy credentials.
- **Seeing a Daytona sandbox:** every result carries `sandbox_id`. Set `CLAWNET_DAYTONA_KEEP=1` to keep the sandbox visible in the Daytona dashboard (it auto-deletes after 30 minutes).
- **Network:** Daytona's lower tiers restrict outbound internet, so network-heavy targets may show less egress there than in Docker.

---

## 10. Running it

```powershell
# 1. TrueForge (installs into .trueforge/ on first run)
python -m clawforge trueforge            # http://localhost:8790

# 2. ClawNet capabilities as MCP tools
python -m clawforge serve                # http://127.0.0.1:8765/mcp

# 3. Supermemory Local (optional; stores news and threat intel for semantic search)
& "C:\Program Files\Git\bin\bash.exe" scripts/supermemory-local.sh   # :6767, inside WSL Ubuntu

# 4. The operator console (first run offers /setup)
python -m clawforge
```

### Console commands

| Command | What it does |
|---|---|
| *(any text)* | Hands the job to the agent |
| `/watch` | Split screen: live connections table, agent output, prompt box |
| `/news` | Crawls live security news (CISA, NVD, MITRE, GitHub, MSRC, Unit 42, Malwarebytes, Talos) and stores it in Supermemory |
| `/news <query>` | Searches stored news: Supermemory first, then the local cache |
| `/status` | Checks the OpenAI key, TrueForge, the MCP server (including old code), registration and the sandbox |
| `/tools` | Lists the 21 tools with their tier |
| `/setup` | Pushes the provider, connector and agent into TrueForge |
| `/new` · `/clear` · `/help` · `/quit` | New session · clear the agent log (in `/watch`) · help · exit |

In `/watch`: Enter sends, ↑/↓ pages through connections, PgUp/PgDn scrolls the agent log, Tab cycles the filter, `y`/`n` answers an approval, and Esc leaves.

---

## 11. Configuration (`.env`)

| Variable | Purpose |
|---|---|
| `OPENAI_API_KEY` | Model key for ClawNet's explanations. `/setup` also copies it into TrueForge for the agent. |
| `OPENAI_MODEL` / `CLAWFORGE_MODEL` | Model for verdict explanations / model for the agent |
| `TRUEFORGE_BASE_URL` | TrueForge server (default `http://localhost:8790`) |
| `CLAWFORGE_HOST`, `CLAWFORGE_PORT`, `CLAWFORGE_TOKEN` | MCP server bind address and bearer token (auto-generated into `~/.clawnet/clawforge_token` if empty) |
| `CLAWFORGE_SANDBOX_TIMEOUT` | Maximum seconds per agent sandbox run (default 180) |
| `DAYTONA_API_KEY`, `DAYTONA_API_URL`, `DAYTONA_TARGET` | Daytona sandbox (primary) |
| `CLAWNET_SANDBOX_BACKEND` | Force `daytona` or `docker` |
| `CLAWNET_DAYTONA_KEEP` | `1` keeps the Daytona sandbox after the run, for inspection |
| `FIRECRAWL_API_KEY` | Live news and threat-intel crawling |
| `SUPERMEMORY_API_KEY`, `SUPERMEMORY_API_URL` | Supermemory Local (default `http://localhost:6767`) |

---

## 12. Operational notes (learned the hard way)

- **Use `python -m clawforge trueforge`, not `npx`.** On Windows, npm 11's `npx` install lock times out on a package this size (`ECOMPROMISED / Lock compromised`). The command installs TrueForge with a plain `npm install`.
- **TrueForge blocks loopback MCP URLs by default.** The `trueforge` command allowlists only the ClawForge MCP host (`OUTBOUND_URL_ALLOWED_HOSTS`) and raises `MCP_REQUEST_TIMEOUT_MS`, so a full sandbox run fits in one tool call.
- **TrueForge keeps its own copy of the OpenAI key.** After changing `OPENAI_API_KEY`, run `/setup`, or the agent keeps using the old key (e.g. `429: no credits remaining`).
- **Restart `serve` after code changes.** Python loads code once, at startup. `/status` flags an MCP server that is running older code than what's on disk.
- **Empty `.env` values mean unset.** `CLAWNET_THREAT_CACHE_PATH=` used to send cache writes to the current directory, where they failed silently. Empty values now fall back to the defaults.
