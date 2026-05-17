# Sentinel — Architecture & How Everything Works

## High-Level System Architecture

```mermaid
graph TB
    subgraph Frontend["Frontend (React 19 + Tailwind 4) :3000"]
        Dashboard["Dashboard<br/>Live pod grid + MTTR"]
        AuditLog["Audit Log<br/>Search + CSV/JSON export"]
        WarRoom["War Room<br/>NLP Chat + AI"]
        ChaosLab["Chaos Lab<br/>Inject failures + track"]
        Traces["Traces<br/>LLM reasoning + timing"]
        Logs["Pod Logs<br/>Real-time colorized"]
        Blockchain["Blockchain View<br/>Stellar on-chain records"]
    end

    subgraph Nginx["Nginx Reverse Proxy"]
        Proxy["/api/* → backend:8000<br/>/ws → WebSocket"]
    end

    subgraph Backend["Backend (FastAPI + LangGraph) :8000"]
        API["REST API + WebSocket"]
        Pipeline["7-Stage LangGraph Pipeline"]
        Agents["Multi-Agent Swarm<br/>Commander, Scout, Doctor,<br/>Executor, Comms"]
        SlackBot["Slack Bot<br/>HITL + NLP Control"]
        BlockchainClient["Stellar Client<br/>Soroban Contract"]
        Predictor["Predictive Engine<br/>OOM + Trend Analysis"]
        RunbookCache["Runbook Cache<br/>Fingerprint → Cached Fix"]
        Tracer["LLM Tracer<br/>Per-call timing + I/O"]
    end

    subgraph K8s["Kubernetes Cluster"]
        NS["Namespace: k8swhisperer-demo"]
        RBAC["RBAC: ServiceAccount + Role<br/>+ ClusterRole (read-only)"]
        Pods["Pods | Deployments | HPAs"]
        Events["Events | Nodes"]
    end

    subgraph External["External Services"]
        Slack["Slack<br/>Approval buttons + NLP"]
        Stellar["Stellar Testnet<br/>Immutable audit trail"]
        Prometheus["Prometheus<br/>Memory + CPU metrics"]
        LLM["Claude API<br/>via LiteLLM"]
        GitHub["GitHub<br/>Auto-generated fix PRs"]
    end

    Frontend --> Nginx --> Backend
    Pipeline --> K8s
    Agents --> K8s
    SlackBot --> Slack
    BlockchainClient --> Stellar
    Predictor --> Prometheus
    Pipeline --> LLM
    Pipeline --> GitHub
    RunbookCache -.->|"Cache hit = skip LLM"| Pipeline
```

---

## The 7-Stage Pipeline (Core Brain)

This is the exact LangGraph state machine. Runs every 45 seconds.

```mermaid
flowchart TD
    START((START)) --> OBSERVE

    OBSERVE["1. OBSERVE<br/>────────────<br/>Poll K8s API:<br/>• Pod statuses<br/>• Events (last 5min)<br/>• Deployment rollouts<br/>• HPA scaling status<br/>• Node conditions<br/><br/>Skip: kube-system,<br/>kube-public, etc.<br/><br/>READ-ONLY. No writes."]

    OBSERVE --> DETECT

    DETECT["2. DETECT<br/>────────────<br/>LLM classifies into 8 types<br/><br/>Validates:<br/>• restartCount > 3<br/>• pending > 5 min<br/>• rolling update filter<br/>• 10-min dedup cache<br/>• confidence >= 0.5"]

    DETECT -->|"No anomalies"| END1((END))
    DETECT -->|"Anomalies found"| CACHE_CHECK

    CACHE_CHECK{"Runbook Cache<br/>────────────<br/>SHA256(type|pattern|<br/>resource)[:16]<br/><br/>Only returns if<br/>previous success=True"}

    CACHE_CHECK -->|"CACHE HIT<br/>0 LLM calls, ~8s"| EXECUTE
    CACHE_CHECK -->|"CACHE MISS"| DIAGNOSE

    DIAGNOSE["3. DIAGNOSE<br/>────────────<br/>Evidence per anomaly type:<br/><br/>CrashLoop: prev logs +<br/>current logs + describe +<br/>events<br/><br/>OOMKilled: describe +<br/>prev logs + Deployment<br/>lookup<br/><br/>Pending: describe +<br/>node capacity<br/><br/>Logs chunked to 12k chars<br/>LLM RCA with evidence"]

    DIAGNOSE --> PLAN

    PLAN["4. PLAN<br/>────────────<br/>LLM proposes from WHITELIST:<br/>• delete_pod<br/>• patch_deployment_resources<br/>• rollback_deployment<br/>• scale_deployment<br/>• cordon_node<br/>• no_op<br/><br/>Validations:<br/>• Unknown action → fallback<br/>• Confidence clamped [0,1]<br/>• Namespace forced to<br/>  anomaly's namespace<br/>• Min blast_radius enforced<br/>  (LLM can't lower it)"]

    PLAN --> SAFETY

    SAFETY{"5. SAFETY GATE<br/>────────────<br/>PURE FUNCTION (no LLM)<br/><br/>auto = confidence > 0.8<br/>AND blast == 'low'<br/>AND NOT destructive<br/><br/>ALL THREE must be true"}

    SAFETY -->|"All 3 true"| EXECUTE
    SAFETY -->|"Any fails"| HITL

    HITL["5b. HITL NODE<br/>────────────<br/>Send Slack: Approve/Reject<br/><br/>Dedup: skip if same anomaly<br/>already pending (10-min TTL)<br/><br/>interrupt() suspends graph<br/>State checkpointed to disk<br/><br/>Waits for human...<br/>(could be hours)"]

    HITL -->|"APPROVED"| EXECUTE
    HITL -->|"REJECTED"| EXPLAIN

    EXECUTE["6. EXECUTE<br/>────────────<br/>HARDCODED if-else:<br/><br/>if delete_pod:<br/>  → walk ownership chain<br/>  → scale Deploy to 0<br/><br/>if patch_deployment:<br/>  → parse K8s units<br/>  → calculate +50%<br/>  → merge patch<br/><br/>if rollback_deployment:<br/>  → prior ReplicaSet<br/><br/>if no_op:<br/>  → do nothing<br/><br/>Guards: DRY_RUN, resource<br/>exists, thread lock,<br/>namespace check"]

    EXECUTE --> VERIFY

    VERIFY{"VERIFY<br/>────────────<br/>Health check with backoff:<br/>5s, 10s, 20s, 40s, 60s"}

    VERIFY -->|"Success"| EXPLAIN
    VERIFY -->|"Fail + retries < 3"| DIAGNOSE
    VERIFY -->|"Fail + retries >= 3"| EXPLAIN

    EXPLAIN["7. EXPLAIN<br/>────────────<br/>LLM summary (< 200 words)<br/><br/>Then in parallel:<br/>• Write audit log<br/>• Send Slack notification<br/>• Store runbook (if success)<br/>• Record to blockchain<br/>• Trigger GitHub PR"]

    EXPLAIN --> END2((END))

    style START fill:#10b981,color:#fff
    style END1 fill:#ef4444,color:#fff
    style END2 fill:#10b981,color:#fff
    style SAFETY fill:#f59e0b,color:#000
    style HITL fill:#3b82f6,color:#fff
    style EXECUTE fill:#ef4444,color:#fff
    style CACHE_CHECK fill:#8b5cf6,color:#fff
    style VERIFY fill:#f59e0b,color:#000
```

---

## Safety Architecture (Why LLM Can't Break Things)

```mermaid
flowchart TB
    LLM_OUTPUT["LLM Output<br/>(action, confidence, blast_radius)"]

    LLM_OUTPUT --> L1

    subgraph L1["Layer 1: RBAC (Kubernetes)"]
        RBAC["ServiceAccount: k8swhisperer-agent<br/>─────────────────────────<br/>Namespaced Role (k8swhisperer-demo):<br/>  pods: get,list,watch,delete,patch<br/>  pods/log: get<br/>  events: get,list,watch<br/>  deployments: get,list,watch,patch,update<br/>  replicasets: get,list,watch<br/>─────────────────────────<br/>ClusterRole (READ-ONLY):<br/>  nodes: get,list,watch<br/>  metrics: get,list<br/>─────────────────────────<br/>NO cluster-admin<br/>NO secrets<br/>NO namespace deletion"]
    end

    L1 --> L2

    subgraph L2["Layer 2: Action Whitelist"]
        WL["ALLOWED_ACTIONS =<br/>{delete_pod, patch_deployment_resources,<br/>rollback_deployment, scale_deployment,<br/>cordon_node, no_op}<br/>─────────────────────────<br/>Unknown action → hardcoded fallback"]
    end

    L2 --> L3

    subgraph L3["Layer 3: Blast Radius Floors"]
        BRF["DeploymentStalled → min 'high' (always HITL)<br/>NodeNotReady → min 'high' (always HITL)<br/>Pending → min 'medium' (always HITL)<br/>ImagePullBackOff → min 'medium' (always HITL)<br/>CPUThrottling → min 'medium' (always HITL)<br/>─────────────────────────<br/>LLM says 'low'? Code overrides it."]
    end

    L3 --> L4

    subgraph L4["Layer 4: Safety Gate (Pure Function)"]
        SG["auto = confidence > 0.8<br/>AND blast_radius == 'low'<br/>AND action NOT in DESTRUCTIVE_ACTIONS<br/>─────────────────────────<br/>DESTRUCTIVE = {rollback_deployment,<br/>drain_node, delete_namespace,<br/>scale_down, force_delete_pod, cordon_node}<br/>─────────────────────────<br/>ALL THREE must be true → auto<br/>ANY fails → human approval"]
    end

    L4 --> L5

    subgraph L5["Layer 5: Namespace Guards"]
        NS["PROTECTED: kube-system, kube-public,<br/>kube-node-lease, default<br/>─────────────────────────<br/>Plan namespace forced = anomaly namespace<br/>Cross-namespace injection blocked"]
    end

    L5 --> L6

    subgraph L6["Layer 6: Execution Guards"]
        EG["Per-resource thread lock (5s timeout)<br/>Resource existence pre-check<br/>DRY_RUN mode (simulate only)<br/>Health verification (5 attempts, 135s)<br/>Max 3 retry cycles"]
    end

    L6 --> L7

    subgraph L7["Layer 7: Audit & Accountability"]
        AU["Every stage → audit_log.json<br/>Every LLM call → traces.json<br/>Every incident → Stellar blockchain<br/>Slack notifications with attribution<br/>HMAC-SHA256 webhook verification"]
    end

    style L1 fill:#fee2e2,color:#000
    style L2 fill:#fef3c7,color:#000
    style L3 fill:#fef3c7,color:#000
    style L4 fill:#dbeafe,color:#000
    style L5 fill:#e0e7ff,color:#000
    style L6 fill:#ede9fe,color:#000
    style L7 fill:#d1fae5,color:#000
```

---

## Slack Integration Flow

```mermaid
sequenceDiagram
    participant Pipeline as LangGraph Pipeline
    participant SafetyGate as Safety Gate
    participant HITL as HITL Node
    participant Slack as Slack
    participant Human as Human Operator
    participant Executor as Execute Node

    Pipeline->>SafetyGate: Plan (action, confidence, blast_radius)

    alt confidence > 0.8 AND blast = low AND !destructive
        SafetyGate->>Executor: Auto-execute
        Executor->>Executor: Hardcoded if-else action
        Executor->>Pipeline: Result (success/failure)
    else Any condition fails
        SafetyGate->>HITL: Route to human
        HITL->>Slack: Send Block Kit message<br/>[Approve] [Reject]
        HITL->>HITL: interrupt() — graph suspended
        Note over HITL: State checkpointed to disk<br/>Can wait hours...

        Human->>Slack: Clicks Approve/Reject
        Slack->>HITL: Webhook (HMAC verified + replay check)
        HITL->>HITL: Resume graph via Command(resume={approved})

        alt Approved
            HITL->>Executor: Execute remediation
            Executor->>Executor: Hardcoded if-else action
            Executor->>Pipeline: Result
        else Rejected
            HITL->>Pipeline: Skip to Explain
        end
    end
```

---

## Observation Loop

```mermaid
flowchart TD
    START((Loop Start)) --> CLEAR["Clear stale dedup entries<br/>(older than 10 min)"]
    CLEAR --> THREAD["Generate thread_id<br/>obs-{uuid[:8]}"]
    THREAD --> RUN["Run full pipeline<br/>(observe → detect → ... → explain)"]
    RUN --> CHECK{"Multiple<br/>anomalies?"}
    CHECK -->|"Yes"| MULTI["Process up to 4 more<br/>each on own thread_id"]
    CHECK -->|"No"| MARK
    MULTI --> MARK["Mark all in dedup cache"]
    MARK --> SLEEP["Sleep 45 seconds"]
    SLEEP --> START

    ERR["On exception:<br/>log error, continue"]
    RUN -.->|"error"| ERR
    ERR --> SLEEP

    style START fill:#10b981,color:#fff
    style ERR fill:#ef4444,color:#fff
```

---

## Runbook Cache (Self-Learning System)

```mermaid
flowchart LR
    subgraph First["First Time (~45s, 4 LLM calls)"]
        D1[Detect] --> DG1[Diagnose<br/>LLM call 1]
        DG1 --> P1[Plan<br/>LLM call 2]
        P1 --> E1[Execute]
        E1 --> EX1[Explain<br/>LLM call 3-4]
        EX1 --> STORE["Store in cache<br/>fingerprint = SHA256<br/>(type|pattern|kind)[:16]<br/><br/>Only if success=True"]
    end

    subgraph Second["Repeat (~8s, 0 LLM calls)"]
        D2[Detect] --> HIT{"Cache<br/>Hit?"}
        HIT -->|"Yes"| E2[Execute<br/>cached plan]
        E2 --> EX2[Explain]
        EX2 --> INC["hit_count += 1"]
    end

    STORE -.->|"Same fingerprint"| HIT

    style STORE fill:#8b5cf6,color:#fff
    style HIT fill:#8b5cf6,color:#fff
```

---

## Multi-Agent Swarm

```mermaid
flowchart TD
    CMD["COMMANDER AGENT<br/>(Supervisor)<br/>─────────────<br/>Decides which agent<br/>to call based on phase"]

    CMD --> SCOUT
    CMD --> DOCTOR
    CMD --> EXEC
    CMD --> COMMS

    SCOUT["SCOUT AGENT<br/>─────────────<br/>READ-ONLY recon<br/><br/>Tools:<br/>• get_pods<br/>• get_events<br/>• get_nodes<br/>• get_deployments<br/><br/>Cannot write anything"]

    DOCTOR["DOCTOR AGENT<br/>─────────────<br/>Root Cause Analysis<br/><br/>Tools:<br/>• get_pod_logs<br/>• describe_pod<br/>• get_events<br/><br/>Cannot write anything"]

    EXEC["EXECUTOR AGENT<br/>─────────────<br/>Remediation<br/><br/>Tools:<br/>• delete_pod<br/>• patch_resources<br/>• rollback_deploy<br/><br/>GUARDS:<br/>Protected namespaces<br/>blocked"]

    COMMS["COMMS AGENT<br/>─────────────<br/>Notifications<br/><br/>Tools:<br/>• send_message<br/>• send_approval<br/><br/>Cannot execute<br/>any k8s actions"]

    style CMD fill:#f59e0b,color:#000
    style SCOUT fill:#10b981,color:#fff
    style DOCTOR fill:#3b82f6,color:#fff
    style EXEC fill:#ef4444,color:#fff
    style COMMS fill:#8b5cf6,color:#fff
```

---

## Blockchain Recording Flow

```mermaid
sequenceDiagram
    participant Explain as Explain Node
    participant Client as Stellar Client (Python)
    participant Soroban as Soroban Contract (Rust)
    participant Testnet as Stellar Testnet

    Explain->>Client: Record incident (background thread)
    Client->>Client: Convert types to ScVal<br/>confidence → u32 (0-10000)
    Client->>Soroban: Build transaction<br/>invoke("store_incident", params)
    Client->>Testnet: Simulate transaction (dry-run)
    Testnet-->>Client: Simulation OK
    Client->>Testnet: Submit transaction
    Testnet-->>Client: tx_hash
    Client->>Client: extend_ttl() prevents data expiry
    Client-->>Explain: {tx_hash, explorer_url}

    Note over Explain: NON-FATAL: If blockchain fails,<br/>incident still processed normally
```

---

## Data Flow: Detection to Resolution

```mermaid
flowchart TD
    K8S["K8s Cluster<br/>(kubectl read-only)"] --> RAW["Raw Signals<br/>pods, events,<br/>deploys, HPAs"]

    RAW --> CLASSIFY["LLM Classifier<br/>8 anomaly types<br/>+ confidence"]

    CLASSIFY --> VALIDATE["Validation Filters<br/>restartCount > 3<br/>pending > 5min<br/>rolling update check<br/>dedup cache"]

    VALIDATE --> EVIDENCE["Evidence Gathering<br/>(per anomaly type)<br/>logs, describe,<br/>events, node caps"]

    EVIDENCE --> RCA["LLM Diagnosis<br/>evidence-cited RCA"]

    RCA --> PLAN_LLM["LLM Plan<br/>action + confidence<br/>+ blast_radius"]

    PLAN_LLM --> VALIDATE2["Plan Validation<br/>• whitelist check<br/>• confidence clamp<br/>• namespace lock<br/>• blast floor enforce"]

    VALIDATE2 --> GATE{"Safety Gate<br/>(pure if-else)"}

    GATE -->|"Safe"| AUTO["Auto-Execute"]
    GATE -->|"Risky"| HUMAN["Human Approval<br/>(Slack)"]

    HUMAN -->|"Approved"| APPROVED_EXEC["Execute"]
    HUMAN -->|"Rejected"| SKIP["Skip → Explain"]

    AUTO --> EXEC_LOGIC
    APPROVED_EXEC --> EXEC_LOGIC

    EXEC_LOGIC["Hardcoded if-else<br/>(NOT LLM-generated cmds)<br/><br/>delete_pod → scale to 0<br/>patch → memory math +50%<br/>rollback → prior RS"]

    EXEC_LOGIC --> HEALTH{"Health Check<br/>5s,10s,20s,40s,60s"}

    HEALTH -->|"Healthy"| EXPLAIN_NODE
    HEALTH -->|"Fail, retries<3"| RCA
    HEALTH -->|"Fail, retries>=3"| EXPLAIN_NODE

    SKIP --> EXPLAIN_NODE

    EXPLAIN_NODE["Explain<br/>• Audit log<br/>• Slack notify<br/>• Blockchain record<br/>• Runbook cache<br/>• GitHub PR"]

    style GATE fill:#f59e0b,color:#000
    style EXEC_LOGIC fill:#ef4444,color:#fff
    style HUMAN fill:#3b82f6,color:#fff
    style EXPLAIN_NODE fill:#10b981,color:#fff
    style VALIDATE2 fill:#fef3c7,color:#000
```
