# K8sWhisperer — Architecture & Agent System

## Our 5 Agents

| Agent | Model | Role | Tools |
|-------|-------|------|-------|
| **Commander** | Opus | Supervisor — decides which agent to call | Delegates only |
| **Scout** | Sonnet | Cluster recon — gathers data | `get_pods`, `get_events`, `get_nodes` (READ-ONLY) |
| **Doctor** | Opus | Root cause analysis — deep reasoning | `get_logs`, `describe_pod` (READ-ONLY) |
| **Executor** | Sonnet | Remediation — executes fixes | `delete_pod`, `patch_deploy`, `rollback` (WRITE) |
| **Comms** | Sonnet | Notifications — talks to humans | `send_slack_message`, `send_approval` (SLACK) |

---

## Full System Architecture

```mermaid
graph TB
    subgraph K8s["Kubernetes Cluster"]
        PODS[Pods]
        EVENTS[Events]
        DEPLOY[Deployments]
        HPA[HPA]
    end

    subgraph Pipeline["7-Stage LangGraph Pipeline"]
        OBS["1. OBSERVE<br/>Poll every 45s"]
        DET["2. DETECT<br/>LLM classifies anomalies"]
        DIAG["3. DIAGNOSE<br/>Fetch logs → LLM root cause"]
        PLAN["4. PLAN<br/>LLM generates fix"]
        GATE["5. SAFETY GATE"]
        EXEC["6. EXECUTE<br/>kubectl + verify loop"]
        EXPL["7. EXPLAIN<br/>Summary + audit + Slack"]
    end

    subgraph Routing["Safety Routing"]
        AUTO["AUTO-EXECUTE<br/>conf>0.8, blast=low"]
        HITL["HITL<br/>Slack Approve/Reject"]
    end

    subgraph Agents["Multi-Agent Swarm"]
        CMD["Commander<br/>Opus"]
        SCT["Scout<br/>Sonnet"]
        DOC["Doctor<br/>Opus"]
        EXE["Executor<br/>Sonnet"]
        COM["Comms<br/>Sonnet"]
    end

    subgraph Storage["Integrations"]
        AUDIT["Audit Log"]
        RUNBOOK["Runbook Cache"]
        SLACK["Slack"]
        CHAIN["Stellar Blockchain"]
        DASH["React Dashboard"]
    end

    K8s --> OBS --> DET --> DIAG --> PLAN --> GATE
    GATE -->|Safe| AUTO --> EXEC
    GATE -->|Risky| HITL -->|Approved| EXEC
    HITL -->|Rejected| EXPL
    EXEC -->|Success| EXPL
    EXEC -->|"Failure (retry<3)"| DIAG
    EXPL --> AUDIT & RUNBOOK & SLACK & CHAIN

    CMD --> SCT & DOC & EXE & COM

    style OBS fill:#1e40af,color:#fff
    style DET fill:#7c3aed,color:#fff
    style DIAG fill:#0891b2,color:#fff
    style PLAN fill:#d97706,color:#fff
    style GATE fill:#dc2626,color:#fff
    style EXEC fill:#ea580c,color:#fff
    style EXPL fill:#059669,color:#fff
    style AUTO fill:#16a34a,color:#fff
    style HITL fill:#dc2626,color:#fff
    style CMD fill:#7c3aed,color:#fff
```

---

## Pipeline Flow — Step by Step

```mermaid
sequenceDiagram
    participant K8s as Kubernetes
    participant OBS as 1. Observe
    participant DET as 2. Detect (LLM)
    participant DIAG as 3. Diagnose (LLM)
    participant PLAN as 4. Plan (LLM)
    participant GATE as 5. Safety Gate
    participant EXEC as 6. Execute
    participant EXPL as 7. Explain (LLM)
    participant SLK as Slack

    loop Every 45 seconds
        OBS->>K8s: get pods, events, deployments
        K8s-->>DET: raw cluster signals

        Note over DET: LLM #1: Classify anomalies
        DET-->>DIAG: CrashLoopBackOff on pod/xyz

        DIAG->>K8s: kubectl logs --previous + describe
        Note over DIAG: LLM #2: Root cause analysis
        DIAG-->>PLAN: "Exit code 1, no startup command"

        Note over PLAN: LLM #3: Generate remediation
        PLAN-->>GATE: delete_pod, conf=0.9, blast=low

        alt Safe action
            GATE->>EXEC: AUTO-EXECUTE
            EXEC->>K8s: delete pod
            EXEC->>EXEC: Verify (5s, 10s, 20s backoff)
        else Risky action
            GATE->>SLK: Approve/Reject buttons
            SLK-->>EXEC: Human approved
        end

        Note over EXPL: LLM #4: Plain-English summary
        EXPL->>SLK: Post notification
    end
```

---

## Safety Gate Decision

```mermaid
graph LR
    IN[Plan] --> C1{Confidence > 0.8?}
    C1 -->|No| HITL[HITL — Ask Human]
    C1 -->|Yes| C2{Blast = low?}
    C2 -->|No| HITL
    C2 -->|Yes| C3{Non-destructive?}
    C3 -->|No| HITL
    C3 -->|Yes| AUTO[AUTO-EXECUTE]

    style AUTO fill:#16a34a,color:#fff
    style HITL fill:#dc2626,color:#fff
```

**All 3 must be true for auto-execution:**
- Confidence > 80%
- Blast radius = low (affects 1 pod only)
- Action is NOT in destructive list (rollback, drain, cordon, force-delete)

---

## Agent RBAC Isolation

```mermaid
graph LR
    subgraph "Read Only"
        S[Scout]
        D[Doctor]
    end
    subgraph "Write"
        E[Executor]
    end
    subgraph "Comms"
        C[Comms]
    end

    S -->|get_pods, get_events, get_nodes| K8S[(K8s API)]
    D -->|get_logs, describe_pod| K8S
    E -->|delete, patch, rollback, scale| K8S
    C -->|messages, approvals| SLACK[(Slack)]

    S -.->|CANNOT write| K8S
    E -.->|CANNOT read logs| K8S
    C -.->|CANNOT touch cluster| K8S

    style S fill:#0284c7,color:#fff
    style D fill:#7c3aed,color:#fff
    style E fill:#ea580c,color:#fff
    style C fill:#0891b2,color:#fff
```

Each agent only has the tools it needs. Scout can look but can't touch. Executor can fix but can't read sensitive logs. This is **RBAC at the agent level**.

---

## Self-Correction Loop

```mermaid
graph LR
    E[Execute] --> V{Pod healthy?}
    V -->|Yes| X[Explain & Log]
    V -->|"No (retry < 3)"| D[Re-diagnose]
    V -->|"No (retries done)"| X
    D --> P[Re-plan] --> E

    style E fill:#ea580c,color:#fff
    style D fill:#0891b2,color:#fff
    style X fill:#059669,color:#fff
```

If a fix fails, the agent doesn't give up — it re-analyzes with the failure context and tries a different approach. Up to 3 retries.

---

## Where LLM is Called (4 times per incident)

| Stage | LLM Call | Input | Output |
|-------|----------|-------|--------|
| **Detect** | LLM #1 | Raw cluster events (pods, statuses, K8s events) | Anomaly classification (type, severity, confidence) |
| **Diagnose** | LLM #2 | kubectl logs, describe, events for specific pod | Root cause analysis citing evidence |
| **Plan** | LLM #3 | Diagnosis text | Remediation plan (action, confidence, blast_radius) |
| **Explain** | LLM #4 | Full incident context | Plain-English summary for humans |
