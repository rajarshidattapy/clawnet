# K8sWhisperer

**Autonomous Kubernetes Incident Response Agent**

> When production breaks at 3am, engineers spend 40 minutes grepping logs. K8sWhisperer does it in 90 seconds -- autonomously.

## What is K8sWhisperer?

K8sWhisperer is a team of specialized AI agents that continuously monitors your Kubernetes cluster, detects anomalies, diagnoses root causes, plans remediation actions, and executes fixes -- while routing risky actions through human-in-the-loop approval via Slack.

## Architecture

```
                    +----------------------+
                    |  INCIDENT COMMANDER  |   Claude Opus (reasoning)
                    |     (Supervisor)     |
                    +----------+-----------+
                               |
            +------------------+------------------+
            |                  |                  |
   +--------v--------+ +------v------+ +---------v---------+
   |   SCOUT AGENT   | |DOCTOR AGENT | |  EXECUTOR AGENT   |
   |  (Sonnet/fast)  | |  (Opus)     | |   (Sonnet/fast)   |
   |                 | |             | |                   |
   | get_pods        | | get_logs    | | delete_pod        |
   | get_events      | | describe    | | patch_deploy      |
   | get_nodes       | | prometheus  | | rollback          |
   | top_pods        | | LLM RCA     | | verify_fix        |
   +-----------------+ +-------------+ +-------------------+
```

### 7-Stage Pipeline

1. **Observe** -- Polls cluster state every 30 seconds
2. **Detect** -- LLM classifies anomalies from raw events
3. **Diagnose** -- Specialist sub-agent analyzes logs, events, and metrics
4. **Plan** -- Generates remediation plan with confidence score and blast radius
5. **Safety Gate** -- Routes to auto-execute (low risk) or human approval (high risk)
6. **Execute** -- Runs kubectl action with verify loop
7. **Explain & Log** -- Plain-English summary, Slack notification, audit trail

## Key Features

- **Multi-Agent Swarm** -- 4 specialized agents with isolated RBAC permissions
- **Predictive Alerting** -- Detects OOM before it crashes using memory trend analysis
- **Self-Evolving Runbooks** -- Learns from past incidents, gets faster over time
- **Chaos Engineering Mode** -- "Break Things" button for live testing
- **Safety Gate + HITL** -- Destructive actions require Slack approval
- **Blockchain Audit Trail** -- Every incident recorded on Stellar testnet
- **War Room Chat** -- Natural language interface to query the agent

## Supported Anomaly Types

| Anomaly | Severity | Auto-Fix |
|---------|----------|----------|
| CrashLoopBackOff | HIGH | Yes |
| OOMKilled | HIGH | Yes |
| Evicted Pod | LOW | Yes |
| Pending Pod | MED | HITL |
| ImagePullBackOff | MED | HITL |
| CPU Throttling | MED | HITL |
| Deployment Stalled | HIGH | HITL |
| Node NotReady | CRITICAL | HITL |

## Tech Stack

- **Orchestration**: LangGraph StateGraph with conditional edges and checkpointing
- **LLM**: Claude Opus/Sonnet via LiteLLM
- **MCP Server**: FastMCP with typed kubectl tools
- **HITL**: Slack Block Kit + FastAPI webhook
- **Frontend**: React + Tailwind CSS + Vite
- **Blockchain**: Stellar Soroban smart contract on testnet
- **Cluster**: Minikube with RBAC-scoped ServiceAccount

## Quick Start

```bash
# 1. Setup minikube
./scripts/setup-minikube.sh

# 2. Configure environment
cp .env.example .env
# Edit .env with your API keys

# 3. Install dependencies
pip install -r requirements.txt
cd frontend && npm install && cd ..

# 4. Start the system
./scripts/run-all.sh
```

## Project Structure

```
k8swhisperer/
├── src/
│   ├── graph/          # LangGraph pipeline (7 stages)
│   ├── agents/         # Multi-agent swarm (Commander, Scout, Doctor, Executor)
│   ├── skills/         # MCP Skills system
│   ├── mcp_server/     # kubectl + Slack MCP tools
│   ├── prediction/     # Predictive alerting (OOM countdown)
│   ├── knowledge/      # Self-evolving runbook cache
│   ├── chaos/          # Chaos engineering injector
│   ├── slack/          # Slack bot + HITL webhook
│   ├── api/            # FastAPI server + War Room
│   └── blockchain/     # Stellar testnet integration
├── k8s/                # Kubernetes manifests (RBAC, demo scenarios)
├── contracts/          # Soroban smart contract (Rust)
├── frontend/           # React + Tailwind dashboard
└── scripts/            # Setup and deployment scripts
```

## RBAC Security

K8sWhisperer uses a **least-privilege ServiceAccount** -- no cluster-admin:
- Pods: get, list, watch, delete, patch (namespaced)
- Deployments: get, list, watch, patch, update (namespaced)
- Nodes: get, list, watch (cluster-scoped, read-only)
- No namespace deletion, no secret access

## Project Vision

Reduce Kubernetes incident response from 40+ minutes of manual log-grepping to under 90 seconds of autonomous detection, diagnosis, and remediation — with safety gates ensuring the agent never destroys what it's trying to protect.

## Deployed Smart Contract

- **Network**: Stellar Testnet (Soroban)
- **Contract ID**: `CBRRAMDMSR2ZJ5F5MNTOXEOQUYJLMTTODEGHOVQZYRJV5VV7LS4JC5OX`
- **Explorer**: [View on Stellar Expert](https://stellar.expert/explorer/testnet/contract/CBRRAMDMSR2ZJ5F5MNTOXEOQUYJLMTTODEGHOVQZYRJV5VV7LS4JC5OX)
- **Functions**: `store_incident()`, `get_incident()`, `get_count()`, `list_incident_ids()`
- **Integration**: Every resolved incident is automatically recorded on-chain from the explain node. Frontend reads live on-chain data via `/api/blockchain/status` and `/api/blockchain/incidents`.

## UI Screenshots

> Screenshots available in `docs/` and in the demo video.

## Future Scope

- **Multi-cluster support** — Monitor multiple K8s clusters from a single agent
- **Custom anomaly types** — User-defined detection rules beyond the 8 built-in types
- **PagerDuty/OpsGenie integration** — Route HITL approvals to existing on-call tools
- **Permanent fix PRs** — Auto-generate GitHub PRs to update deployment manifests (prototype implemented)
- **Cost optimization** — Detect over-provisioned resources and recommend right-sizing
- **Incident correlation** — Group related anomalies (e.g., OOMKill + Evicted on same node = node pressure)

## Team

Built during the 2026 Hackathon (36 hours)
