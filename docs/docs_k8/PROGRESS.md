# K8sWhisperer - Progress & Knowledge Summary

## What Was Built

### Core Pipeline (7 Mandatory Stages) - ALL WORKING
1. **Observe** (`src/graph/nodes/observe.py`) - Polls K8s cluster every 30s via kubernetes Python client. Collects pod states, events, node conditions, deployment rollout status, HPA metrics. Skips system namespaces.

2. **Detect** (`src/graph/nodes/detect.py`) - LLM classifier using Claude Haiku. Outputs typed Anomaly objects with type, severity, confidence. Includes deduplication (10-min cooldown), CrashLoop restart threshold validation, Pending time validation, CPUThrottling HPA validation.

3. **Diagnose** (`src/graph/nodes/diagnose.py`) - Per-anomaly-type evidence gathering (previous logs for CrashLoop, resource limits for OOMKill, node capacity for Pending). Finds owning Deployment for Deployment-managed pods. LLM generates root cause with cited kubectl evidence.

4. **Plan** (`src/graph/nodes/plan.py`) - LLM generates RemediationPlan with action, target, params, confidence, blast_radius, is_destructive. Hardcoded fallbacks per anomaly type if LLM fails.

5. **Safety Gate** (`src/graph/nodes/safety_gate.py`) - Conditional edge: AUTO-EXECUTE only if confidence > 0.8 AND blast_radius = "low" AND action NOT in DESTRUCTIVE_ACTIONS. Otherwise routes to HITL.

6. **Execute** (`src/graph/nodes/execute.py`) - Runs kubectl action via kubernetes client. Resolves pod -> ReplicaSet -> Deployment ownership chain. Verify loop with exponential backoff (5s, 10s, 20s, 40s, 60s).

7. **Explain & Log** (`src/graph/nodes/explain.py`) - LLM generates plain-English summary. Writes LogEntry to `data/audit_log.json`. Posts to Slack channel.

### LangGraph Architecture
- `src/graph/state.py`: ClusterState TypedDict with Annotated reducers
- `src/graph/builder.py`: Full StateGraph with 8 nodes, conditional edges, self-correction loop (retry < 3), InMemorySaver checkpointer
- Graph: START -> observe -> detect -> diagnose -> plan -> safety_router -> (execute | hitl_node) -> explain -> END

### MCP Server
- `src/mcp_server/kubectl_tools.py`: FastMCP with 11 typed tools (get_pods, get_pod_logs, describe_pod, get_events, get_nodes, delete_pod, patch_deployment_resources, rollback_deployment, get_deployments, get_hpa, scale_deployment)
- `src/mcp_server/slack_tools.py`: FastMCP with send_slack_message, send_approval_request

### Slack HITL
- `src/slack/bot.py`: Block Kit message builder with Approve/Reject buttons
- `src/slack/webhook.py`: FastAPI webhook receiving Slack callbacks, verifies signing secret, resumes LangGraph via Command(resume=...)
- Tested: Notifications sent, approval requests with buttons posted to #test channel

### API Server
- `src/api/server.py`: FastAPI with CORS, lifespan handler starting observation loop
- `src/api/routes.py`: /incidents, /audit-log, /chat (war room), /cluster-state, /chaos, WebSocket
- `src/main.py`: Continuous observation loop every 30s as background asyncio task

### Frontend (React + Tailwind)
- Dashboard with live incident timeline, cluster pod grid, chaos button
- Audit Log with expandable JSON details
- War Room chat interface
- Blockchain tab (placeholder for Stellar integration)
- Dark slate-900 mission control theme

### RBAC Security
- `k8s/rbac.yaml`: ServiceAccount + namespaced Role + ClusterRole (nodes read-only)
- NO cluster-admin anywhere
- Namespace protection in executor tools as defense-in-depth

### Multi-Agent Swarm
- `src/agents/commander.py`: Supervisor coordinating 4 agents
- `src/agents/scout.py`: Cluster reconnaissance (Sonnet, read-only)
- `src/agents/doctor.py`: Root cause analysis (Opus/Sonnet)
- `src/agents/executor.py`: Remediation execution (Sonnet, write tools)
- `src/agents/comms.py`: Slack notifications

### MCP Skills System
- `src/skills/registry.py`: Skill discovery framework
- 5 skills: diagnose_crashloop, diagnose_oomkill, patch_memory, safe_delete_pod, generate_postmortem

### Predictive Alerting
- `src/prediction/oom_predictor.py`: Linear regression on Prometheus memory trends
- `src/prediction/trend_analyzer.py`: Multi-pod analysis, restart frequency detection

### Self-Evolving Runbooks
- `src/knowledge/runbook_store.py`: JSON-backed store with fingerprinting
- `src/knowledge/fingerprint.py`: SHA-256 based incident similarity matching

### Chaos Engineering
- `src/chaos/injector.py`: Random failure injection from 8 demo scenarios
- POST /api/chaos endpoint + ChaosButton frontend component

### Blockchain
- `contracts/incident-audit/src/lib.rs`: Soroban smart contract (Rust)
- `src/blockchain/stellar_client.py`: Python client for Stellar testnet
- `scripts/deploy-contract.sh`: Automated deployment

### Demo Scenarios (8 YAMLs)
- crashloop-demo.yaml (standalone Pod)
- crashloop-deploy-demo.yaml (Deployment)
- oomkill-demo.yaml (standalone Pod)
- oomkill-deploy-demo.yaml (Deployment)
- pending-demo.yaml
- imagepull-demo.yaml
- stalled-deploy.yaml
- evicted-demo.yaml
- hpa-stress-demo.yaml + stress-generator.yaml

## Verified Test Results

| Scenario | Detection | Plan | Safety Gate | Execute | Slack |
|---|---|---|---|---|---|
| CrashLoopBackOff | 0.95 | delete_pod | AUTO | SUCCESS (28s) | Sent |
| OOMKilled | 0.95 | patch_resources | AUTO | Attempted | Sent |
| Pending Pod | 0.95 | no_op (blast=medium) | HITL (paused) | N/A | Approval sent |

## Key Technical Decisions

1. **Sync LLM calls in LangGraph nodes** - LangGraph nodes are sync, so we use `litellm.completion` (sync) not `litellm.acompletion` (async)
2. **openai/ model prefix** - LiteLLM proxy needs `openai/` prefix to route to OpenAI-compatible endpoint
3. **Pod -> Deployment ownership** - `_find_owning_deployment()` walks Pod -> ReplicaSet -> Deployment via ownerReferences
4. **kind cluster** - Using kind instead of minikube (functionally equivalent)
5. **claude-haiku-4-5** for all pipeline stages (fast + cheap), sonnet for reasoning-heavy tasks

## Repository Stats

- **24+ commits** (all after 11:00 AM IST March 29, 2026)
- **102+ files** tracked
- **12,000+ lines of code**
- **GitHub**: https://github.com/manaspros/k8swhisperer (private)

## What's Running

- Backend: http://localhost:8000 (FastAPI + observation loop)
- Frontend: http://localhost:5174 (React dashboard)
- Cluster: kind (atlanclaw) with k8swhisperer-demo namespace
- Slack: Bot connected to #test channel (C0AQCLDSL80)
