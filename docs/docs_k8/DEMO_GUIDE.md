# K8sWhisperer — Demo & Explanation Guide

---

## What You're Looking At

### k9s Terminal View (Kubernetes Cluster)

When you open k9s, you see the **live state of every pod** in the cluster. Here's what each column means:

| Column | Meaning |
|--------|---------|
| **NAME** | The pod's name in Kubernetes |
| **READY** | `0/1` = container isn't ready, `1/1` = healthy |
| **STATUS** | Current state — Running, Error, CrashLoopBackOff, OOMKilled, etc. |
| **RESTARTS** | How many times K8s has restarted this container |
| **AGE** | How long since the pod was created |

**Color coding in k9s:**
- Red/Orange rows = something is wrong (Error, CrashLoop, OOMKilled)
- Green = healthy and running
- Yellow = transitional state (starting up, terminating)

---

## What Happens When You Press "Chaos"

### Step 1: Chaos Injection
The **Chaos button** on the dashboard calls `POST /api/chaos?count=3` which randomly picks 3 failure scenarios from 9 available types and deploys them as Kubernetes YAML manifests.

### Step 2: Pods Start Failing
Within seconds, k9s shows new pods appearing in **red/orange** — they're crashing, out of memory, or stuck. This is what you saw:

```
crashloop-demo                          0/1   Error              2    41s
crashloop-deploy-demo-8c5d88484-76fkb   0/1   Error              3    76s
imagepull-demo                          0/1   ImagePullBackOff   0    52s
oomkill-deploy-demo-7dd47d664c-6p9tv    0/1   OOMKilled          2    31s
stalled-deploy-demo-855b4dcf96-*        0/1   Running            0    4m
```

### Step 3: Agent Detects (every 30 seconds)
The observation loop polls the cluster, collects all pod states and events, and sends them to Claude Haiku which classifies each issue:

```
observe  → collected 35 events/signals
detect   → found CrashLoopBackOff on crashloop-deploy-demo
detect   → found ImagePullBackOff on imagepull-demo
detect   → found OOMKilled on oomkill-deploy-demo
detect   → found DeploymentStalled on stalled-deploy-demo
```

### Step 4: Agent Diagnoses, Plans, and Decides
For each anomaly, the agent:
1. **Diagnoses** — fetches logs, events, and resource info, then LLM explains the root cause
2. **Plans** — generates a fix with confidence score and blast radius
3. **Safety Gate** — decides auto-execute or ask human

```
CrashLoopBackOff → delete_pod     → confidence=0.90, blast=low    → AUTO EXECUTE
OOMKilled        → patch_memory   → confidence=0.85, blast=low    → AUTO EXECUTE
ImagePullBackOff → alert_human    → confidence=0.95, blast=medium → HITL (Slack)
DeploymentStalled→ rollback       → confidence=0.92, blast=high   → HITL (Slack)
```

### Step 5: Auto-Fix or Ask Human
- **Safe fixes** (low blast radius + high confidence) → agent fixes immediately, pod goes green in k9s
- **Risky fixes** (high blast radius or destructive) → agent sends Slack message with Approve/Reject buttons

### Step 6: Explain and Log
After every incident, the agent:
- Writes a plain-English summary
- Saves to audit log (`data/audit_log.json`)
- Posts to Slack channel
- Caches the solution as a runbook for next time
- Records on Stellar blockchain

---

## The 5 Failure Types You Saw

### 1. CrashLoopBackOff (crashloop-demo)
**What broke:** A container that exits immediately on startup. Kubernetes keeps restarting it, creating an endless crash-restart loop.

**What the agent does:** Detects restartCount > 3, fetches previous container logs to find the crash reason (exit code 1 = app error), deletes the pod so the Deployment recreates a fresh one. Auto-executed because it's low risk.

### 2. OOMKilled (oomkill-deploy-demo)
**What broke:** A container tried to use more memory than its limit (e.g., 200Mi usage with 50Mi limit). Kubernetes kills it.

**What the agent does:** Reads the current memory limit, calculates +50% increase, patches the Deployment with new limits. The pod restarts with more memory. Auto-executed.

### 3. ImagePullBackOff (imagepull-demo)
**What broke:** The container image doesn't exist (`registry.example.com/nonexistent:latest`). Kubernetes can't download it.

**What the agent does:** Detects the pull failure, diagnoses "image not found at registry", but CAN'T fix it automatically (needs correct image name from a human). Routes to Slack for human approval. Blast radius = medium.

### 4. DeploymentStalled (stalled-deploy-demo)
**What broke:** A Deployment with 3 replicas where none pass the readiness probe (wrong port configured). Shows as `0/1 Running` — container runs but isn't ready.

**What the agent does:** Detects `updatedReplicas != availableReplicas`, diagnoses the readiness probe failure, plans a rollback to the previous version. But rollback is **destructive** and **high blast radius** → always routes to Slack HITL for human approval.

### 5. Evicted (when injected)
**What broke:** A pod consuming too much disk/memory on the node, causing Kubernetes to evict it.

**What the agent does:** Detects eviction event, deletes the evicted pod to clean up. Auto-executed because it's low risk.

---

## How to Demo This

### Show 1: The Chaos Flow (2 minutes)
1. Open **k9s** in one terminal (shows live cluster)
2. Open **Dashboard** (http://localhost:5174) in browser
3. Press the **Chaos button** on the Chaos Lab tab
4. Watch k9s → pods go red
5. Wait 30s → agent detects and starts fixing
6. Watch k9s → pods turn green as agent fixes them
7. Check **Audit Log tab** → full pipeline trace for each incident

### Show 2: Safety Gate in Action (1 minute)
1. Point at the DeploymentStalled incident → routed to HITL
2. Open **Slack** → show the Approve/Reject buttons
3. Click Approve → agent executes the rollback
4. k9s updates → deployment rolls back

### Show 3: War Room Chat (30 seconds)
1. Go to **War Room tab**
2. Type: "What's wrong with the cluster?"
3. Agent responds with real-time cluster analysis

### Show 4: Learning (30 seconds)
1. Trigger chaos again (more CrashLoops)
2. Point out: "First CrashLoop took ~45s. This one took ~8s because the agent cached the runbook."
3. Show Audit Log → `[CACHED RUNBOOK]` prefix on diagnosis

---

## Architecture at a Glance

```
 Kubernetes Cluster (kind)
        |
        v
 [OBSERVE] ──30s poll──> pods, events, deployments, HPA
        |
        v
 [DETECT] ──Claude Haiku──> classify into 8 anomaly types
        |
        v
 [DIAGNOSE] ──kubectl + LLM──> root cause with evidence
        |
        v
 [PLAN] ──LLM──> action + confidence + blast_radius
        |
        v
 [SAFETY GATE]
   /          \
  AUTO        HITL
  (safe)    (risky)
   |           |
   v           v
 [EXECUTE]  [SLACK] ──Approve/Reject──>
   |           |
   v           v
 [EXPLAIN] ──> audit log + Slack + runbook cache + blockchain
```

---

## Numbers to Quote

- **30 seconds** — detection latency (observation poll interval)
- **~45 seconds** — full incident cycle (first time)
- **~8 seconds** — repeat incident (cached runbook)
- **0.8+ confidence** — threshold for auto-execution
- **3 retries** — self-correction attempts before giving up
- **48+ incidents** — successfully processed in testing
- **81% success rate** — auto-fix remediations
- **9 runbooks** — cached from resolved incidents
- **0 cluster-admin** — principle of least privilege
