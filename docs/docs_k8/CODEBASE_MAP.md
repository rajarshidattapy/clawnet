# Codebase Map — What Every File Does

## Backend (`src/`)

### Core

| File | Purpose |
|---|---|
| `src/main.py` | Entry point. Starts FastAPI server, launches the 45s observation loop in a background thread, initializes Slack Socket Mode listener |
| `src/config.py` | Pydantic settings loaded from `.env`. Feature flags (`ENABLE_PREDICTIVE_ALERTING`, `ENABLE_RUNBOOK_CACHE`, `ENABLE_MULTI_AGENT`, `ENABLE_BLOCKCHAIN`, `ENABLE_MULTI_NAMESPACE`), model config, Slack tokens, K8s config, Stellar keys |
| `src/models.py` | TypedDicts for `Anomaly`, `RemediationPlan`, `LogEntry`. Defines `DESTRUCTIVE_ACTIONS` frozenset (rollback, drain, delete_namespace, scale_down, force_delete, cordon) |
| `src/github_pr.py` | Auto-creates GitHub PRs with permanent fix suggestions (e.g. patched YAML manifests) after remediation |

### LangGraph Pipeline (`src/graph/`)

This is the core 7-stage incident response state machine.

| File | Purpose |
|---|---|
| `src/graph/state.py` | `ClusterState` TypedDict — the shared state object flowing through the graph. Fields: raw_signals, anomalies, evidence, diagnosis, plan, execution_result, explanation, audit_log, stage_timings, incident_id, retries. Uses `Annotated` reducers (`operator.add` for lists, `operator.or_` for dicts) |
| `src/graph/builder.py` | Builds the LangGraph `StateGraph`. Defines nodes (observe, detect, diagnose, plan, safety_gate, hitl_node, execute, explain) and conditional edges. `_timed()` wrapper records per-stage execution time. Routing functions: `_has_anomalies()`, `_hitl_decision()`, `_verify_check()` |

### Pipeline Nodes (`src/graph/nodes/`)

Each file is one stage of the pipeline:

| File | Stage | What It Does |
|---|---|---|
| `src/graph/nodes/observe.py` | 1. OBSERVE | Polls K8s cluster for pods, events, deployments, HPAs. Multi-namespace support with skip list (`kube-system`, `kube-public`, etc.). Synthesizes HPA scaling events. Normalizes all K8s objects to generic dicts for LLM consumption |
| `src/graph/nodes/detect.py` | 2. DETECT | Sends raw signals to LLM classifier. Validates output: checks restartCount > 3 for CrashLoop, age > 5min for Pending, CPU > 80% for throttling. Rolling update false-positive filter. 10-minute dedup sliding window prevents re-alerting |
| `src/graph/nodes/diagnose.py` | 3. DIAGNOSE | Gathers anomaly-specific evidence (logs, pod describe, events, node capacity). Different evidence strategy per anomaly type. Chunks logs for LLM context. Calls LLM diagnostician for root cause analysis with evidence citations |
| `src/graph/nodes/plan.py` | 4. PLAN | LLM generates remediation plan with confidence, blast_radius, is_destructive flag. Hardcoded fallback plans per anomaly type if LLM fails. **Minimum blast_radius enforcement** — LLM cannot downgrade below required floors |
| `src/graph/nodes/safety_gate.py` | 5. SAFETY GATE | Pure function (no LLM). Routes to auto-execute if `confidence > 0.8 AND blast_radius == "low" AND NOT destructive`. Otherwise routes to HITL |
| `src/graph/nodes/hitl.py` | 5b. HITL | Sends Slack approval request with Block Kit buttons. Tracks pending approvals (10-min TTL) to prevent duplicate messages. Calls `interrupt()` to suspend LangGraph. Resumes via `Command(resume=...)` when Slack button clicked |
| `src/graph/nodes/execute.py` | 6. EXECUTE | Runs the remediation action. Pod ownership chain resolution (Pod -> ReplicaSet -> Deployment). Smart crash loop breaking (scale to 0, not pod delete). Dynamic memory patching with unit math. Per-resource thread locks. Post-execution health verification with exponential backoff (5s, 10s, 20s, 40s, 60s) |
| `src/graph/nodes/explain.py` | 7. EXPLAIN | LLM generates incident summary. Writes audit log entry. Sends Slack notification with resolution. Records to blockchain (if enabled). Triggers GitHub PR for permanent fix |

### Multi-Agent Swarm (`src/agents/`)

Alternative to the pipeline — uses LangGraph supervisor pattern with specialized agents.

| File | Agent | What It Does |
|---|---|---|
| `src/agents/commander.py` | Commander | Supervisor agent that orchestrates the other 4 agents. Decides which agent to delegate to based on incident phase. Uses LangGraph's `create_react_agent` with supervisor routing |
| `src/agents/scout.py` | Scout | Read-only cluster reconnaissance. Gathers pod statuses, events, deployments, node health. Cannot modify anything |
| `src/agents/doctor.py` | Doctor | Root cause analysis specialist. Deep investigation using logs, events, config analysis. Produces diagnosis with evidence citations |
| `src/agents/executor.py` | Executor | Safe remediation execution. Namespace validation prevents cross-namespace attacks. Resource existence pre-checks. Retry with verification |
| `src/agents/comms.py` | Comms | Incident communication via Slack. Formats rich Block Kit messages. Handles approval request formatting |

### LLM Integration (`src/llm/`)

| File | Purpose |
|---|---|
| `src/llm/client.py` | LiteLLM wrapper for model-agnostic LLM calls. Async + sync modes. Retry with exponential backoff (max 3). **3-stage JSON extraction fallback** (direct parse -> fenced block -> bracket scan). Per-thread trace context via `threading.local()` |
| `src/llm/prompts.py` | All system prompts: CLASSIFIER (8 anomaly types with trigger signals), DIAGNOSTICIAN (evidence-based RCA), PLANNER (safe remediation with confidence/blast_radius), EXPLAINER (incident summary), SCOUT/DOCTOR/EXECUTOR/COMMS/COMMANDER (agent-specific) |

### MCP Tools (`src/mcp_server/`)

FastMCP tool servers that agents call via Model Context Protocol.

| File | Purpose |
|---|---|
| `src/mcp_server/kubectl_tools.py` | K8s operations as MCP tools: `get_pods()`, `get_pod_logs()`, `describe_pod()`, `get_events()`, `get_nodes()`, `delete_pod()`, `patch_deployment_resources()`, `rollback_deployment()`, `get_deployments()`. Uses K8s Python client internally |
| `src/mcp_server/slack_tools.py` | Slack operations as MCP tools: `send_slack_message()`, `send_approval_request()` |
| `src/mcp_server/prometheus_tools.py` | Prometheus query tools: `query_prometheus()`, `query_range()`. Used by OOM predictor for memory metrics |

### Slack Integration (`src/slack/`)

| File | Purpose |
|---|---|
| `src/slack/bot.py` | Slack message builder. Block Kit formatting with severity emojis, field layouts, dividers. Builds approval request messages with Approve/Reject buttons embedding `thread_id` + `incident_id` as JSON in button values |
| `src/slack/listener.py` | Socket Mode listener for real-time Slack events. Handles `app_mention` and `message` events. **NLP intent classification** via regex: cluster_status, incident_query, chaos_trigger, nlp_command (22 action verbs). Graph resumption for approvals runs in thread-pool executor |
| `src/slack/webhook.py` | HTTP webhook endpoint for Slack interactive payloads. HMAC-SHA256 signature verification. Replay attack prevention (5-min window). `hmac.compare_digest()` for timing-attack safety. Resumes LangGraph with approved/rejected decision |

### Blockchain (`src/blockchain/`)

| File | Purpose |
|---|---|
| `src/blockchain/stellar_client.py` | Stellar Soroban smart contract client. Converts Python types to Soroban scvals. Simulates transaction before submission. Returns Stellar Explorer URL. Non-fatal — blockchain failure doesn't block incident response |
| `src/blockchain/record.py` | Data structures for blockchain incident records. Serialization/deserialization between Python dicts and Soroban contract parameters |

### Predictive Analytics (`src/prediction/`)

| File | Purpose |
|---|---|
| `src/prediction/oom_predictor.py` | Queries Prometheus for `container_memory_working_set_bytes`. Fits **linear regression** (`numpy.polyfit`) on 5-min memory samples. Calculates R-squared confidence, growth rate (MB/sec), time-to-OOM. Alerts if OOM predicted within 30-min horizon |
| `src/prediction/trend_analyzer.py` | Analyzes restart timestamps from `container.lastState.terminated.finishedAt` + BackOff events. Compares recent vs earlier average restart intervals. Flags **accelerating restarts** if recent intervals are 20%+ faster. Calculates acceleration factor |

### Knowledge Base (`src/knowledge/`)

| File | Purpose |
|---|---|
| `src/knowledge/fingerprint.py` | Generates deterministic incident fingerprints: `SHA256(anomaly_type \| error_pattern \| resource_kind)[:16]`. Normalizes error patterns by stripping numbers/timestamps for consistent hashing |
| `src/knowledge/runbook_store.py` | Thread-safe runbook cache. Stores diagnosis + plan for fingerprinted incidents. Only caches successful resolutions. Tracks hit_count, avg_resolution_time, cache_hit_rate. Returns cached runbook on fingerprint match — bypasses entire LLM pipeline |

### Skills (`src/skills/`)

Pre-built remediation skill modules.

| File | Purpose |
|---|---|
| `src/skills/registry.py` | Skill registry that maps skill names to handler functions. Extensible plugin system |
| `src/skills/diagnose_crashloop.py` | CrashLoopBackOff-specific diagnosis logic |
| `src/skills/diagnose_oomkill.py` | OOMKilled-specific diagnosis logic |
| `src/skills/patch_memory.py` | Memory resource patching skill with K8s unit math |
| `src/skills/safe_delete_pod.py` | Safe pod deletion with ownership chain awareness |
| `src/skills/generate_postmortem.py` | Generates post-incident report for completed incidents |

### Chaos Engineering (`src/chaos/`)

| File | Purpose |
|---|---|
| `src/chaos/injector.py` | Chaos scenario injection engine. Randomly samples N scenarios from K8s YAML manifests. Deploys via `kubectl apply` with async subprocess. **Staggered injection** (10s delays between scenarios) to prevent cluster overload. Cleanup function deletes all demo resources |

### Tracing (`src/tracing/`)

| File | Purpose |
|---|---|
| `src/tracing/tracer.py` | LLM call tracing. Records per-call: timing (ms), model name, input/output preview (500 chars), full text (5000 chars), char counts. Keyed by `trace_id` (incident_id). Thread-safe JSON file writes. Thread-local context isolation |

### API (`src/api/`)

| File | Purpose |
|---|---|
| `src/api/server.py` | FastAPI app factory. Mounts routes, CORS middleware, startup/shutdown hooks. Starts observation loop and Slack listener on startup |
| `src/api/routes.py` | All REST endpoints + WebSocket. `GET /health`, `GET /api/incidents`, `GET /api/audit-log`, `POST /api/chat` (war room with LLM context), `GET /api/cluster-state`, `POST /api/chaos` + `/api/chaos/inject` + `/api/chaos/cleanup` + `/api/chaos/scenarios`, `GET /api/pods/{ns}/{name}/logs`, `GET /api/traces`, `GET /api/blockchain/status` + `/incidents`. WebSocket connection manager for real-time broadcasts |

### Utilities (`src/utils/`)

| File | Purpose |
|---|---|
| `src/utils/k8s_client.py` | K8s client loader. Tries in-cluster config first (for pod deployment), falls back to kubeconfig file. Idempotent loading with global flag. Returns CoreV1Api, AppsV1Api, AutoscalingV1Api |
| `src/utils/log_chunker.py` | Keeps last 200 lines of logs, prepends truncation header. Splits on newline boundaries (never breaks log lines). 12k char limit for LLM context |
| `src/utils/audit.py` | Writes structured audit log entries to JSON file. Thread-safe file append. ISO-8601 UTC timestamps |
| `src/utils/backoff.py` | Exponential and jittered retry utilities |
| `src/utils/concurrency.py` | Thread pool management utilities |

---

## Frontend (`frontend/src/`)

| File | Purpose |
|---|---|
| `frontend/src/main.tsx` | React app entry point. Mounts `<App />` to DOM |
| `frontend/src/App.tsx` | Root component. Tab navigation with animated underline (measures DOM refs for smooth transition). Live clock display. 6 tabs: Dashboard, Audit Log, War Room, Chaos Lab, Traces, Blockchain. Blockchain status polling every 15s. Stellar contract info display |
| `frontend/src/lib/api.ts` | API client. Typed fetch wrappers for all backend endpoints: incidents, audit-log, chat, chaos, cluster-state, traces, pod logs, blockchain |
| `frontend/src/types/index.ts` | TypeScript interfaces: `Incident`, `AuditEntry`, `ClusterState`, `Pod`, `Node`, `ChatMessage`, `Trace`, `BlockchainStatus`, `BlockchainIncident` |

### Components

| File | Purpose |
|---|---|
| `frontend/src/components/Dashboard.tsx` | Mission control. Live pod grid with status dots. Incident cards with severity/confidence. Cost savings metrics (time saved, engineer-hours). MTTR trending. Live pipeline activity feed with stage timings. Browser notifications on new incidents. Skeleton shimmer loading states |
| `frontend/src/components/IncidentCard.tsx` | Individual incident display. Deterministic color hash per anomaly type (`hash * 31 + charCode` mod palette). Stage progress dots (detect -> analyze -> plan -> act -> verify) with glow on completion. Confidence factor breakdown. Blast radius indicator. Active incident pulse animation |
| `frontend/src/components/AuditLog.tsx` | Searchable audit trail. Expandable rows with syntax-highlighted JSON (regex-based coloring: cyan keys, emerald values, purple booleans, amber numbers). CSV/JSON export with proper quote escaping. 10s auto-refresh. Stage color badges |
| `frontend/src/components/WarRoom.tsx` | Chat interface for cluster queries. Markdown-lite renderer (fenced code blocks, inline code, bold). Quick action chips. Auto-scroll on new messages. Typing indicator with staggered dot animation |
| `frontend/src/components/ChaosButton.tsx` | Chaos engineering lab. Scenario selector with dynamic icons/colors. 3-second countdown animation before injection. Captures baseline audit count, polls every 2s showing only new entries. Auto-stops after 3 minutes. Stage progression badges per incident |
| `frontend/src/components/MTTRChart.tsx` | Analytics. Recharts ComposedChart with dual Y-axes (incident count bars + confidence area). Aggregates incidents by anomaly_type. Bar colors by severity. Custom gradient fills |
| `frontend/src/components/TracesView.tsx` | LLM reasoning traces. Groups by incident_id. Expandable input/output previews (> 200 chars). Duration bars (green < 2s, amber < 5s, red > 5s). Token approximation (chars / 4). Text unescaping for proper rendering |
| `frontend/src/components/PodLogsView.tsx` | Pod log viewer. Line-by-line colorization (ERROR=rose, WARN=amber). Line numbers. Tail control (50/100/500 lines). Previous container logs toggle. Auto-scroll |

---

## Smart Contract (`contracts/incident-audit/`)

| File | Purpose |
|---|---|
| `contracts/incident-audit/src/lib.rs` | Soroban (Stellar) smart contract in Rust. `IncidentRecord` struct with 7 fields. `DataKey` enum for type-safe storage keys. 4 methods: `store_incident()` (stores + updates count + index + extends TTL), `get_incident()`, `get_count()`, `list_incident_ids()`. TTL extension prevents data expiry. Unit test included |

---

## Kubernetes Manifests (`k8s/`)

| File | Purpose |
|---|---|
| `k8s/namespace.yaml` | Creates `k8swhisperer-demo` namespace |
| `k8s/rbac.yaml` | ServiceAccount (`k8swhisperer-agent`) + Role (namespaced: pods CRUD, logs read, events read, deployments CRUD, replicasets read) + ClusterRole (cluster-wide read-only: nodes, metrics) |
| `k8s/demo-scenarios/crashloop-demo.yaml` | Pod that exits with code 1 every 2s (CrashLoopBackOff) |
| `k8s/demo-scenarios/crashloop-deploy-demo.yaml` | Deployment with failing containers (tests ownership chain walk) |
| `k8s/demo-scenarios/oomkill-demo.yaml` | Pod exceeding 50Mi memory limit (OOMKilled) |
| `k8s/demo-scenarios/oomkill-deploy-demo.yaml` | Deployment with memory stress (tests Deployment-level remediation) |
| `k8s/demo-scenarios/imagepull-demo.yaml` | Non-existent registry image (ImagePullBackOff) |
| `k8s/demo-scenarios/pending-demo.yaml` | Unschedulable resource request (Pending) |
| `k8s/demo-scenarios/evicted-demo.yaml` | Pod consuming excess resources (Evicted) |
| `k8s/demo-scenarios/stalled-deploy.yaml` | 3 replicas with wrong readiness probe port (DeploymentStalled) |
| `k8s/demo-scenarios/hpa-stress-demo.yaml` | Deployment + HPA + load generator (CPUThrottling) |
| `k8s/demo-scenarios/stress-generator.yaml` | Load generator pod for HPA stress test |
| `k8s/demo-scenarios/node-pressure-demo.yaml` | Memory hog pod triggering node pressure |
| `k8s/fixes/fix-inc-6006-stalled-deploy-demo.yaml` | Example auto-generated fix manifest from GitHub PR integration |

---

## Scripts (`scripts/`)

| File | Purpose |
|---|---|
| `scripts/setup-minikube.sh` | Creates minikube cluster (`k8swhisperer` profile, 4 CPU, 8GB RAM), enables metrics-server, applies namespace + RBAC |
| `scripts/run-all.sh` | Starts backend (uvicorn) + frontend (npm dev) in parallel with colored output. SIGINT cleanup |
| `scripts/docker-setup.sh` | Creates kind cluster, rewrites kubeconfig for Docker networking (`127.0.0.1` -> `host.docker.internal`), builds + starts docker-compose |
| `scripts/deploy-scenarios.sh` | Applies all demo scenario YAMLs to cluster |
| `scripts/deploy-contract.sh` | Builds + deploys Soroban contract to Stellar Testnet. Generates identity, tests with sample incident |
| `scripts/stress-test.sh` | Deploys HPA stress test + load generator |

---

## Root Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | 2 services (backend port 8000, frontend port 3000). Mounts kubeconfig read-only, k8s-data volume for audit logs |
| `Dockerfile.backend` | Python 3.11-slim + kubectl binary. Runs `python -m src.main` |
| `Dockerfile.frontend` | Node 22-alpine build -> Nginx alpine serve. Reverse proxy to backend |
| `nginx.conf` | SPA routing. Proxies `/api/`, `/health`, `/slack/` to backend. WebSocket support |
| `requirements.txt` | Python deps: langgraph, langchain, litellm, fastapi, slack-sdk, kubernetes, stellar-sdk, numpy, mcp |
| `README.md` | Project overview and setup instructions |

---

## Data Flow Summary

```
Observation Loop (45s)
  |
  v
observe.py  -->  Polls K8s API (pods, events, deployments, HPAs)
  |
  v
detect.py   -->  LLM classifies anomalies + validation filters
  |
  v
diagnose.py -->  Gathers evidence per anomaly type + LLM RCA
  |
  v
plan.py     -->  LLM generates remediation + blast radius floors enforced
  |
  v
safety_gate.py --> Pure function: auto-execute or HITL?
  |                    |
  | (auto)             | (needs approval)
  v                    v
execute.py          hitl.py --> Slack approval --> interrupt() --> resume on button click
  |                    |
  |                    v
  |                 execute.py (if approved)
  v
explain.py  -->  Summary + Audit log + Slack notification + Blockchain record + GitHub PR
```
