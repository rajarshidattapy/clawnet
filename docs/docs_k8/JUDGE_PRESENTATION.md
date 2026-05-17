# Sentinel — What's Under the Hood (Judge Presentation)

## What the PS Asked

> "A system that automatically detects issues in a Kubernetes cluster, understands the problem, decides what to do, and either fixes it itself or asks a human for approval."

## PS Requirements — Covered

| Requirement | Implementation |
|---|---|
| Auto-detect issues | 45s polling loop across all namespaces. 8 anomaly types: CrashLoop, OOM, ImagePull, Pending, Evicted, Stalled, CPUThrottling, NodeNotReady |
| Understand the problem | LLM-powered RCA using pod logs, events, descriptions, node conditions with evidence citations |
| Decide what to do | AI planner with confidence scoring, blast radius assessment, destructive action flagging |
| Fix it itself | 6 actions: delete_pod, patch_resources, rollback_deployment, scale_deployment, cordon_node, no_op |
| Ask human for approval | Slack HITL with interactive Approve/Reject buttons. Auto-routes when confidence < 0.8 OR blast_radius != low OR action is destructive |

---

## Beyond the PS — Engineering Decisions That Matter

### 1. Smart Crash Loop Breaking (Not Naive Pod Delete)

Most implementations would just `kubectl delete pod`. K8s recreates it instantly — the loop continues.

Our executor **walks the ownership chain** (Pod -> ReplicaSet -> Deployment) and **scales the Deployment to 0 replicas**, actually breaking the infinite restart loop. There's a fallback for when the original pod is already replaced (OOMKilled) — it matches pod-name prefixes against ReplicaSet names.

**Why it matters**: Shows we understand K8s internals, not just API calls.

---

### 2. The LLM Cannot Lie About Safety

The planner has **hardcoded minimum blast_radius floors** per anomaly type:

- `DeploymentStalled` / `NodeNotReady` -> forced to `"high"` (always HITL)
- `Pending` / `ImagePullBackOff` / `CPUThrottling` -> forced to `"medium"`

Even if the LLM outputs `"blast_radius": "low"` for a stalled deployment, the code **overrides it**. The safety gate then checks three conditions deterministically (no LLM involved):

```
auto_execute = confidence > 0.8 AND blast_radius == "low" AND NOT is_destructive
```

**Why it matters**: We don't blindly trust AI output. Defense-in-depth against hallucination.

---

### 3. Rolling Update False-Positive Filter

The detector doesn't just flag CrashLoopBackOff blindly. Before alerting:

- Checks if restarts are part of a **rolling deployment update** by matching pod names against ReplicaSet prefix patterns
- Only alerts if `restartCount > 3` (ignores initial rollout restarts)
- For CPUThrottling: validates `current_cpu > 80%` of target before triggering
- For Pending pods: validates pod has been stuck **> 5 minutes**

**Why it matters**: Reduces alert fatigue. Production systems do rolling updates constantly — flagging them is a common rookie mistake.

---

### 4. Per-Resource Thread Locking (Race Condition Prevention)

A `threading.Lock` exists per `namespace/pod_name` key with a 5-second acquisition timeout. This prevents two concurrent pipeline runs from both trying to delete the same pod or patch the same deployment simultaneously.

**Why it matters**: Most hackathon projects ignore concurrency. This is production-grade thinking.

---

### 5. LangGraph Interrupt-Resume with Checkpointing

The HITL node calls `interrupt()` which **suspends the entire LangGraph state machine** to disk via MemorySaver. When a Slack button is clicked (could be hours later), the graph resumes from the exact checkpoint with full incident context restored.

This is NOT a polling loop or a webhook that re-runs the pipeline — it's true state machine suspension and resumption.

**Why it matters**: Shows architectural sophistication beyond simple request-response patterns.

---

### 6. Accelerating Restart Detection (Preventive, Not Reactive)

The trend analyzer doesn't just count restarts. It compares **recent average restart intervals vs earlier ones**. If recent intervals are 20%+ faster, it flags "accelerating restarts" with an acceleration factor — before catastrophic failure.

The OOM predictor uses **linear regression** on Prometheus memory metrics to predict OOM **30 minutes before it happens**, calculating memory growth rate (MB/sec) and time-to-OOM.

**Why it matters**: Moves from reactive incident response to predictive alerting.

---

### 7. Three-Stage JSON Extraction Fallback

Our LLM client doesn't depend on JSON mode (not all models support it). It tries:

1. Direct `json.loads()` on full text
2. Extract fenced ` ```json...``` ` code blocks
3. Scan for first `[` or `{`, match closing bracket, parse substring

**Why it matters**: Works with any LLM provider regardless of output format quirks. Resilient by design.

---

### 8. Self-Learning Runbook Cache (Only Stores Successes)

Fingerprint = `SHA256(anomaly_type | error_pattern | resource_kind)[:16]`

- First incident: ~45 seconds (4 LLM calls)
- Repeat incident: ~8 seconds (0 LLM calls) — **5.6x speedup**
- Failed remediations are **never cached** (`success == True` check)
- Tracks hit_count, avg_resolution_time, cache_hit_rate

**Why it matters**: The system gets smarter over time. Failed fixes don't get replayed.

---

### 9. Replay Attack Prevention on Slack Webhooks

The webhook handler:
- Verifies HMAC-SHA256 signatures using Slack's signing secret
- Rejects requests older than 5 minutes (replay attack prevention)
- Uses `hmac.compare_digest()` (timing-attack safe comparison)

**Why it matters**: Most hackathon Slack integrations skip security entirely. We handle it properly.

---

### 10. Pending Approval Deduplication with 10-Min TTL

If the same anomaly is already waiting for Slack approval, the system **skips sending another message** but still interrupts the graph. Entries expire after 10 minutes so re-detection works naturally.

**Why it matters**: Prevents Slack spam during the 45s observation loop while still tracking the anomaly.

---

### 11. HPA Synthetic Event Injection

When an HPA is actively scaling, the observe node emits BOTH the raw HPA status AND a synthetic "HPAScaling" event with `current_replicas`, `desired_replicas`, and CPU utilization — giving the LLM dual signals to reason about.

**Why it matters**: The LLM gets structured data AND human-readable context, improving diagnosis quality.

---

### 12. Cross-Namespace Injection Prevention

The plan validator **forces the target namespace to match the anomaly's namespace**. Even if the LLM hallucinates a namespace like `kube-system`, the code overrides it. System namespaces (`kube-system`, `kube-public`, `kube-node-lease`) are protected at the executor level too.

**Why it matters**: Prevents LLM-driven lateral movement across namespaces. Defense-in-depth.

---

### 13. Dynamic Resource Patching with Unit Math

When the plan says "+50% memory":
1. Reads current limit from Deployment spec
2. Parses K8s memory strings (`512Mi`, `1Gi`, `Ki`, `M`, `G`) to numeric bytes
3. Multiplies by 1.5, converts back to K8s format
4. Falls back to `128Mi` if no current limit exists

**Why it matters**: Not hardcoded values — mathematically correct resource scaling.

---

### 14. Soroban TTL Extension (Blockchain Doesn't Expire)

Every `store_incident()` call in the smart contract also calls `extend_ttl()` — preventing Stellar's automatic data expiry from eating the audit trail. Most Soroban demos miss this and lose data after ~100 ledger entries.

**Why it matters**: Shows we understand the Stellar storage model, not just copy-pasted a tutorial.

---

### 15. Stage Timing Accumulation via LangGraph Reducers

Every pipeline node is wrapped with `_timed()` that records execution time in ms. These accumulate via `Annotated[dict, operator.or_]` reducers in the LangGraph state — giving a full performance breakdown per incident without manual tracking.

**Why it matters**: Built-in observability at the framework level. We can show exactly which stage is the bottleneck.

---

### 16. Multi-Agent Swarm with Isolated RBAC

5 specialized agents, each with constrained capabilities:
- **Scout**: Read-only cluster recon (can't modify anything)
- **Doctor**: Root cause analysis specialist
- **Executor**: Write operations with namespace guards
- **Comms**: Slack notifications only
- **Commander**: Supervisor orchestrating the above

**Why it matters**: Follows principle of least privilege at the agent level, not just the K8s level.

---

### 17. MCP (Model Context Protocol) Tool Abstraction

kubectl operations are exposed as **FastMCP tools** — a clean, typed tool interface that agents call. This means:
- Tools are discoverable and self-documenting
- Can be swapped/extended without changing agent logic
- Prometheus metrics also exposed as MCP tools

**Why it matters**: Forward-looking architecture. MCP is the emerging standard for agent tool use.

---

## Key Numbers

| Metric | Value |
|---|---|
| Detection latency | 30s |
| First incident cycle | ~45s (4 LLM calls) |
| Cached incident cycle | ~8s (0 LLM calls) |
| Auto-fix rate | ~81% |
| Anomaly types | 8 |
| Agents | 5 specialized |
| Chaos scenarios | 7 injectable |
| Frontend views | 6 (Dashboard, Audit, War Room, Chaos Lab, Traces, Logs) |
| RBAC model | Zero cluster-admin |
| Blockchain | Real Soroban contract on Stellar Testnet |
| Safety checks | 4 layers (blast radius floor, safety gate, namespace guard, resource lock) |

---

## One-Liner for Judges

> "The PS asked for detect-diagnose-fix-approve. We built that, plus the LLM can't lie about safety, crash loops are broken at the Deployment level not pod level, the system learns from past fixes, predicts OOMs 30 minutes early, and every incident is immutably recorded on Stellar blockchain."
