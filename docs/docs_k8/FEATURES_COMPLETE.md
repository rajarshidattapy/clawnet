# Sentinel — Complete Feature List

Every feature implemented, organized by category. Each entry references the actual code.

---

## A. CORE PIPELINE (Problem Statement Requirements)

### A1. Automatic Issue Detection
- **45-second polling loop** continuously monitors the K8s cluster (`src/main.py` observation_loop)
- Collects **pod statuses, events, deployments, HPAs, node conditions** (`src/graph/nodes/observe.py`)
- LLM classifies raw signals into **8 anomaly types** with confidence scores (`src/graph/nodes/detect.py`)
- Anomaly types: CrashLoopBackOff, OOMKilled, Pending, ImagePullBackOff, CPUThrottling, Evicted, DeploymentStalled, NodeNotReady

### A2. Problem Understanding (Root Cause Analysis)
- **Anomaly-specific evidence gathering** — different kubectl commands per anomaly type (`src/graph/nodes/diagnose.py`)
  - CrashLoop: previous logs + current logs + pod describe + recent events (4 sources)
  - OOMKilled: pod describe + previous logs + owning Deployment lookup
  - Pending: pod describe + node capacity
  - ImagePullBackOff: pod describe only
- LLM performs **evidence-cited diagnosis** — must reference specific kubectl output (`src/llm/prompts.py` DIAGNOSTICIAN_SYSTEM_PROMPT)
- Log chunking keeps last 200 lines within 12k char limit for LLM context (`src/utils/log_chunker.py`)

### A3. Deciding What to Do (Remediation Planning)
- LLM generates remediation plan with **action, confidence, blast_radius, is_destructive** (`src/graph/nodes/plan.py`)
- Only **6 whitelisted actions** accepted: `delete_pod`, `patch_deployment_resources`, `rollback_deployment`, `scale_deployment`, `cordon_node`, `no_op` (`src/graph/nodes/plan.py` ALLOWED_ACTIONS)
- Unknown actions from LLM are **replaced with hardcoded safe fallback plans** per anomaly type
- Confidence clamped to `[0.0, 1.0]`, invalid blast_radius defaults to `"high"`

### A4. Fixing It Itself (Autonomous Execution)
- **Hardcoded if-else executor** — the LLM does NOT run kubectl directly (`src/graph/nodes/execute.py`)
- Actions are coded logic:
  - `delete_pod`: walks Pod → ReplicaSet → Deployment ownership chain, **scales Deployment to 0** (breaks crash loop properly)
  - `patch_deployment_resources`: parses K8s memory units (Mi, Gi, Ki), calculates +50%, applies strategic merge patch
  - `rollback_deployment`: finds previous ReplicaSet revision, patches Deployment
  - `scale_deployment`: patches replica count
  - `no_op`: does nothing, escalates
- Post-execution **health verification** with exponential backoff: 5s, 10s, 20s, 40s, 60s (`src/graph/nodes/execute.py`)
- **Retry loop**: if fix fails, re-diagnoses and re-plans up to 3 times (`src/graph/builder.py` _verify_check)

### A5. Asking Human for Approval (HITL)
- **Safety gate** is a pure function with zero LLM involvement (`src/graph/nodes/safety_gate.py`):
  ```
  auto_execute = confidence > 0.8 AND blast_radius == "low" AND action NOT destructive
  ```
- If any condition fails → routes to HITL
- **Slack Block Kit** message with Approve/Reject buttons sent (`src/slack/bot.py`)
- Graph **suspends via interrupt()** and state is checkpointed (`src/graph/nodes/hitl.py`)
- Graph resumes when human clicks button — via Slack webhook (`src/slack/webhook.py`)
- Full state restored from checkpoint — can wait hours for approval

---

## B. SAFETY & SECURITY (Critical Engineering)

### B1. LLM Has No Direct Command Access
- The LLM **never generates or executes kubectl commands** directly
- LLM outputs a structured JSON plan (action name + params)
- Execution is **hardcoded if-else logic** that maps action names to specific K8s API calls (`src/graph/nodes/execute.py`)
- Even in the multi-agent swarm, agents call pre-defined MCP tools — not arbitrary shell commands

### B2. Action Whitelist with Fallback
- Only 6 actions are accepted from LLM output (`src/graph/nodes/plan.py` ALLOWED_ACTIONS)
- Any action outside the whitelist → **replaced with hardcoded safe default** for that anomaly type
- Fallback defaults: CrashLoop→delete_pod, OOM→patch_resources, Pending→no_op, etc.

### B3. Blast Radius Floor Enforcement
- LLM cannot downgrade blast_radius below hardcoded minimums (`src/graph/nodes/plan.py`):
  - `DeploymentStalled` → minimum `"high"` (always routes to HITL)
  - `NodeNotReady` → minimum `"high"` (always routes to HITL)
  - `Pending` → minimum `"medium"` (always routes to HITL)
  - `ImagePullBackOff` → minimum `"medium"` (always routes to HITL)
  - `CPUThrottling` → minimum `"medium"` (always routes to HITL)
- Even if LLM says `"blast_radius": "low"`, code overrides it

### B4. Namespace Injection Prevention
- Plan validator **forces target namespace to match anomaly's namespace** (`src/graph/nodes/plan.py`)
- If LLM hallucinates a namespace like `kube-system`, code overrides it
- **Protected namespaces** block at agent level: `kube-system`, `kube-public`, `kube-node-lease`, `default` (`src/agents/executor.py` PROTECTED_NAMESPACES)

### B5. Destructive Action Classification
- `DESTRUCTIVE_ACTIONS` frozenset in code (`src/models.py`):
  - `rollback_deployment`, `drain_node`, `delete_namespace`, `scale_down`, `force_delete_pod`, `cordon_node`
- `delete_pod` is explicitly NOT destructive (K8s controller recreates it)
- Destructive actions **always route to HITL** regardless of confidence

### B6. Per-Resource Thread Locking
- A `threading.Lock` per `namespace/pod_name` key (`src/graph/nodes/execute.py`)
- 5-second acquisition timeout
- Prevents two concurrent pipeline runs from both fixing the same resource simultaneously

### B7. Resource Existence Pre-Check
- Before executing any action, validates the target pod/deployment exists (`src/graph/nodes/execute.py`)
- 404 → skip gracefully, don't error

### B8. DRY_RUN Mode
- `DRY_RUN=True` in config simulates all executions without applying any changes (`src/config.py`)
- Useful for demos and testing

### B9. RBAC Least Privilege
- K8s ServiceAccount `k8swhisperer-agent` (`k8s/rbac.yaml`):
  - **Namespaced Role** (k8swhisperer-demo only): pods (get/list/watch/delete/patch), pods/log (get), events (get/list/watch), deployments (get/list/watch/patch/update), replicasets (get/list/watch)
  - **ClusterRole** (cluster-wide READ-ONLY): nodes (get/list/watch), metrics (get/list)
  - NO cluster-admin. NO secrets access. NO namespace deletion. NO pod creation.

### B10. Slack Webhook Security
- **HMAC-SHA256 signature verification** on every Slack webhook (`src/slack/webhook.py`)
- **Replay attack prevention**: rejects requests older than 5 minutes
- Uses `hmac.compare_digest()` — timing-attack safe comparison

---

## C. INTELLIGENT DETECTION (Beyond Basic Monitoring)

### C1. Rolling Update False-Positive Filter
- Before flagging CrashLoopBackOff, checks if pod restarts are part of a **rolling deployment update** (`src/graph/nodes/detect.py`)
- Matches pod name against ReplicaSet prefix patterns
- Only alerts if `restartCount > 3`

### C2. Validation Filters Per Anomaly Type
- CrashLoop: `restartCount > 3` required (`src/graph/nodes/detect.py`)
- CPUThrottling: `current_cpu > 80%` of target required
- Pending: pod must be stuck **> 5 minutes**
- Confidence threshold: `>= 0.5` or anomaly dropped

### C3. 10-Minute Sliding Window Deduplication
- Same `(anomaly_type, resource)` pair not re-processed within 10 minutes (`src/graph/nodes/detect.py`)
- Prevents alert fatigue and duplicate Slack messages
- Entries expire naturally — anomaly can be re-detected after window

### C4. HITL Pending Approval Dedup
- If the same anomaly is already waiting for Slack approval, **skips sending another message** (`src/graph/nodes/hitl.py`)
- 10-minute TTL on pending approvals
- Graph still interrupts but doesn't spam Slack

### C5. Multi-Anomaly Processing
- Single observation cycle can detect **multiple anomalies** (`src/main.py`)
- Processes up to 4 additional anomalies per cycle, each on its own thread

---

## D. SELF-LEARNING SYSTEM

### D1. Incident Fingerprinting
- `SHA256(anomaly_type | error_pattern | resource_kind)[:16]` (`src/knowledge/fingerprint.py`)
- Error patterns normalized by stripping numbers/timestamps for consistent matching

### D2. Self-Evolving Runbook Cache
- Successful resolutions cached by fingerprint (`src/knowledge/runbook_store.py`)
- Cache hit = **skip entire LLM pipeline** (0 LLM calls, ~8s vs ~45s)
- **Failed fixes are NEVER cached** — `success == True` check
- Tracks: `hit_count`, `avg_resolution_time`, `cache_hit_rate`
- Thread-safe with locking

### D3. Performance Improvement Over Time
- First incident: ~45 seconds (4 LLM calls)
- Repeat incident: ~8 seconds (0 LLM calls)
- **5.6x speedup** as system learns

---

## E. PREDICTIVE ANALYTICS

### E1. OOM Prediction (30-Minute Horizon)
- Queries Prometheus for `container_memory_working_set_bytes` (`src/prediction/oom_predictor.py`)
- **Linear regression** (`numpy.polyfit`) on 5-minute memory samples
- Calculates: memory growth rate (MB/sec), R-squared confidence, time-to-OOM
- Alerts if OOM predicted within 30-minute window

### E2. Accelerating Restart Detection
- Tracks restart timestamps from container `lastState.terminated.finishedAt` (`src/prediction/trend_analyzer.py`)
- Compares recent avg restart intervals vs earlier avg
- Flags if recent intervals are **20%+ faster** (acceleration_factor = earlier_avg / recent_avg)
- Detects degradation **before** catastrophic failure

---

## F. MULTI-AGENT ARCHITECTURE

### F1. 5 Specialized Agents
- **Commander**: Supervisor, orchestrates other agents (`src/agents/commander.py`)
- **Scout**: Read-only cluster recon, cannot write anything (`src/agents/scout.py`)
- **Doctor**: Root cause analysis with evidence gathering (`src/agents/doctor.py`)
- **Executor**: Remediation with namespace guards (`src/agents/executor.py`)
- **Comms**: Slack notification specialist (`src/agents/comms.py`)

### F2. Agent-Level RBAC
- Scout: only gets read tools (get_pods, get_events, get_nodes, get_deployments)
- Executor: gets write tools BUT with PROTECTED_NAMESPACES guard blocking `kube-system` etc.
- Comms: only gets Slack tools
- Each agent has **exactly the tools it needs** — principle of least privilege

### F3. LangGraph Supervisor Pattern
- Commander agent delegates to sub-agents based on incident phase
- Prevents context rot by giving each agent a focused task
- Feature-flagged: `ENABLE_MULTI_AGENT` in config

---

## G. SLACK INTEGRATION

### G1. HITL Approval Flow
- Block Kit messages with severity emoji, incident details, Approve/Reject buttons (`src/slack/bot.py`)
- Button values embed `thread_id` and `incident_id` as JSON for graph resumption
- Message updated in-place when user responds

### G2. NLP Cluster Control (Beyond HITL)
- **@mention** the bot to control the cluster via natural language (`src/slack/listener.py`)
- Intent classification via regex:
  - `status|health|broken|failing` → cluster status report
  - `incident|history|audit` → incident history
  - `inject chaos|break things` → chaos injection
  - `fix|restart|delete|scale|rollback|...` (22 verbs) → NLP command execution
- Socket Mode real-time listener + `/k8s` slash command support

### G3. Incident Notifications
- Rich Slack messages on incident detection, resolution, and escalation
- Severity-specific emoji: `:rotating_light:` CRITICAL, `:warning:` HIGH, `:large_yellow_circle:` MED, `:information_source:` LOW

---

## H. BLOCKCHAIN AUDIT TRAIL

### H1. Stellar Soroban Smart Contract
- Real **Rust contract** deployed on Stellar Testnet (`contracts/incident-audit/src/lib.rs`)
- Data model: `IncidentRecord` with 7 fields (incident_id, anomaly_type, action_taken, timestamp, confidence_score, was_auto_executed, diagnosis_summary)
- Confidence stored as `u32` (0-10000) for on-chain precision

### H2. Immutable Record Storage
- Every completed incident recorded on-chain from explain node (`src/blockchain/stellar_client.py`)
- Transaction simulated before submission (prevents failed txs)
- TTL extended on every write (prevents Stellar data expiry)
- Explorer URL returned: `https://stellar.expert/explorer/testnet/tx/{hash}`

### H3. Non-Fatal Integration
- Blockchain recording runs in background thread
- Failure **never blocks** incident response pipeline
- Feature-flagged: `ENABLE_BLOCKCHAIN`

### H4. Frontend Blockchain View
- Connection status, contract ID, network info (`frontend/src/App.tsx`)
- On-chain incident records browsable with auto/HITL badge, confidence, action
- Link to Stellar Explorer for transaction verification

---

## I. OBSERVABILITY & TRACING

### I1. Full Audit Trail
- Every pipeline stage logged: observe, detect, diagnose, plan, execute, explain (`src/utils/audit.py`)
- Fields: incident_id, timestamp (UTC ISO-8601), stage, summary, details, decision, outcome
- Thread-safe JSON append

### I2. LLM Call Tracing
- Every LLM call recorded (`src/tracing/tracer.py`):
  - Model name, input preview (500 chars), output preview (500 chars)
  - Full text (5000 chars), char counts, duration_ms
- Keyed by incident_id for per-incident analysis
- Thread-local context isolation

### I3. Stage Timing Metrics
- Every pipeline node wrapped with `_timed()` recording execution time in ms (`src/graph/builder.py`)
- Accumulates via LangGraph `Annotated[dict, operator.or_]` reducers
- Shows exactly which stage is the bottleneck

### I4. LLM Retry with Exponential Backoff
- 3 attempts max, `2^attempt` seconds between retries (`src/llm/client.py`)
- 3-stage JSON extraction fallback: direct parse → fenced code block → bracket scanning

---

## J. CHAOS ENGINEERING

### J1. 7 Injectable Failure Scenarios
- CrashLoopBackOff, OOMKilled, ImagePullBackOff, Pending, DeploymentStalled, Evicted, Node Pressure (`src/chaos/injector.py`)
- Each maps to a K8s YAML manifest in `k8s/demo-scenarios/`

### J2. Interactive Chaos Lab (Frontend)
- One-click injection with **3-second countdown animation** (`frontend/src/components/ChaosButton.tsx`)
- Scenario selector with dynamic icons and color coding
- Live pipeline tracking: captures audit log baseline before injection, polls every 2s for new entries
- **Auto-stops** tracking after 3 minutes

### J3. Staggered Injection
- Multiple scenarios deployed with **10-second delays** between each (`src/chaos/injector.py`)
- Prevents overwhelming the cluster with simultaneous failures

### J4. Cleanup
- One-click cleanup of all demo resources (pods + deployments) in the namespace

---

## K. FRONTEND DASHBOARD

### K1. Live Pod Grid
- Real-time pod status dots with color coding (`frontend/src/components/Dashboard.tsx`)
- Polls cluster state periodically

### K2. Incident Cards
- Severity badge, confidence percentage, anomaly type with **deterministic color hash** (`frontend/src/components/IncidentCard.tsx`)
- Stage progress visualization (detect → analyze → plan → act → verify) with glow effects
- Confidence factor breakdown explaining the score
- Active incident pulse animation

### K3. MTTR Trending Chart
- Recharts ComposedChart with dual Y-axes: incident count bars + confidence area (`frontend/src/components/MTTRChart.tsx`)
- Aggregates by anomaly type, sorted by frequency
- Severity-based bar coloring

### K4. War Room Chat
- Conversational AI interface for cluster queries (`frontend/src/components/WarRoom.tsx`)
- **READ-ONLY context**: system prompt says "You have READ-ONLY access... Never pretend you executed a command" (`src/api/routes.py`)
- Markdown-lite rendering (code blocks, inline code, bold)
- Quick action chips, auto-scroll, typing indicator

### K5. Audit Log with Export
- Searchable, expandable audit entries (`frontend/src/components/AuditLog.tsx`)
- **Syntax-highlighted JSON** viewer (regex-based: cyan keys, emerald values, purple booleans, amber numbers)
- **CSV/JSON export** with proper quote escaping + blob URL download
- 10-second auto-refresh

### K6. LLM Traces View
- Groups traces by incident (`frontend/src/components/TracesView.tsx`)
- Expandable input/output previews, duration bars (green <2s, amber <5s, red >5s)
- Token approximation (chars/4)

### K7. Pod Logs View
- Real-time log viewer with line-by-line colorization: ERROR=rose, WARN=amber (`frontend/src/components/PodLogsView.tsx`)
- Line numbers, tail control (50/100/500), previous container logs toggle

### K8. Browser Notifications
- Desktop notifications on new incident detection (`frontend/src/components/Dashboard.tsx`)
- Uses incident_id as notification `tag` for deduplication

### K9. Cost Savings Metrics
- Time saved, engineer-hours, ROI calculations displayed on dashboard

### K10. WebSocket Real-Time Updates
- Connection manager broadcasts incident updates to all connected clients (`src/api/routes.py`)
- One-way push, graceful disconnection handling

---

## L. MCP (MODEL CONTEXT PROTOCOL) TOOLS

### L1. kubectl MCP Tools
- K8s operations exposed as typed, discoverable MCP tools (`src/mcp_server/kubectl_tools.py`):
  - Read: `get_pods`, `get_pod_logs`, `describe_pod`, `get_events`, `get_nodes`, `get_deployments`, `get_hpa`
  - Write: `delete_pod`, `patch_deployment_resources`, `rollback_deployment`, `scale_deployment`

### L2. Slack MCP Tools
- `send_slack_message`, `send_approval_request` (`src/mcp_server/slack_tools.py`)

### L3. Prometheus MCP Tools
- `query_prometheus`, `query_range` for metrics (`src/mcp_server/prometheus_tools.py`)

---

## M. SKILLS FRAMEWORK

### M1. Pluggable Skill Registry
- Decorator-based registration: `@skills_registry.skill(name, description, schema)` (`src/skills/registry.py`)

### M2. Implemented Skills
- `diagnose_crashloop`: Exit code classification (maps 0,1,2,126,127,137,139,143), log analysis (`src/skills/diagnose_crashloop.py`)
- `diagnose_oomkill`: Memory analysis, Prometheus usage query, recommends 1.5x limit rounded to 64Mi (`src/skills/diagnose_oomkill.py`)
- `patch_memory`: Strategic merge patch on Deployment, triggers rolling update (`src/skills/patch_memory.py`)
- `safe_delete_pod`: Namespace guards, polls 30s for replacement pod by labels (`src/skills/safe_delete_pod.py`)
- `generate_postmortem`: LLM-generated Markdown post-mortem report (`src/skills/generate_postmortem.py`)

---

## N. GITHUB INTEGRATION

### N1. Auto-Generated Fix PRs
- After remediation, creates GitHub PR with permanent config fix (`src/github_pr.py`)
- Creates branch: `k8swhisperer/fix-{incident_id[:8]}-{deployment_name}`
- Generates patched YAML manifest (e.g., updated resource limits)
- Commits, pushes, creates PR via `gh` CLI

---

## O. DEPLOYMENT & PORTABILITY

### O1. Docker Compose
- 2-service setup: backend (:8000) + frontend (:3000) (`docker-compose.yml`)
- Kubeconfig mounted read-only, data volume for audit persistence

### O2. Nginx Reverse Proxy
- SPA routing, `/api/*` proxied to backend, WebSocket support (`nginx.conf`)

### O3. Setup Scripts
- `setup-minikube.sh`: Creates cluster (4 CPU, 8GB), enables metrics-server
- `docker-setup.sh`: Kind cluster + Docker networking setup
- `deploy-scenarios.sh`: Applies all demo chaos scenarios
- `deploy-contract.sh`: Builds + deploys Soroban contract to Stellar Testnet
- `run-all.sh`: Parallel backend + frontend startup with colored output

### O4. Feature Flags
- `ENABLE_PREDICTIVE_ALERTING`, `ENABLE_RUNBOOK_CACHE`, `ENABLE_MULTI_AGENT`, `ENABLE_BLOCKCHAIN`, `ENABLE_MULTI_NAMESPACE` (`src/config.py`)
- Every advanced feature can be toggled independently

---

## P. CONFIGURATION & RESILIENCE

### P1. LiteLLM Model Abstraction
- Model-provider agnostic (`src/llm/client.py`)
- Fast model (Haiku/Sonnet) for quick ops, reasoning model (Sonnet) for deep analysis
- Configurable via environment variables

### P2. Error Isolation
- Observation loop: one failure never crashes the loop (`src/main.py`)
- Blockchain: failure never blocks pipeline
- Slack: graceful degradation if unavailable
- Evidence gathering: continues even if one kubectl call fails

### P3. Pod Ownership Chain Resolution
- Walks Pod → ReplicaSet → Deployment via ownerReferences (`src/graph/nodes/execute.py`)
- Fallback: if pod is gone (OOMKilled replacement), matches pod-name prefix against ReplicaSet names
- Ensures remediation targets the correct Deployment, not just the ephemeral Pod

### P4. HPA Synthetic Event Injection
- When HPA is actively scaling, observe node emits BOTH raw HPA status AND a synthetic "HPAScaling" event (`src/graph/nodes/observe.py`)
- Gives LLM dual signals (structured data + human-readable message)

---

## FEATURE COUNT SUMMARY

| Category | Count |
|---|---|
| Core pipeline stages | 7 |
| Anomaly types detected | 8 |
| Remediation actions | 6 |
| Safety layers | 7 (RBAC, whitelist, blast floor, safety gate, namespace guard, resource lock, verification) |
| Specialized agents | 5 |
| Frontend views | 7 (Dashboard, Audit, War Room, Chaos Lab, Traces, Logs, Blockchain) |
| Chaos scenarios | 7 |
| MCP tool sets | 3 (kubectl, Slack, Prometheus) |
| Skills | 5 |
| Predictive algorithms | 2 (OOM regression, restart acceleration) |
| Feature flags | 5 |
| Setup scripts | 6 |
| **Total discrete features** | **60+** |
