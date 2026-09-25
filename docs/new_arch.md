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
                    Agentic Harness
                           │
                           ▼
                  ┌─────────────────┐
                  │  Internal Agent │
                  │     System      │
                  └────────┬────────┘
                           │
                      ┌────▼────┐
                      │TrueForge│
                      │         │
                      │Sessions │
                      │Subagents│
                      │Tooling  │
                      │Approval │
                      └────┬────┘
                           │
                           ▼
                    ┌─────────────┐
                    │   ClawNet   │
                    │     Core    │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
          Network       Sandbox       Policy
          Monitor       Runtime       Engine
              │            │            │
              └────────────┼────────────┘
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
Propose Action
  ↓
Policy Check
  ↓
APPROVAL REQUIRED
  ↓
Human
  ├── Approve → Execute
  └── Reject  → Stop
```

---

## 4. ClawNet Capabilities

Existing ClawNet functionality becomes agent-accessible capabilities:

- **Network monitoring**
- **Policy evaluation**
- **Sandboxed execution**
- **Process inspection**
- **Behavioral analysis**
- **Threat intelligence**
- **Security actions**
- **Memory / evidence**
- **Human approval**

The existing security primitives remain authoritative; the agent cannot override them.

---

## 5. TrueForge Responsibilities

TrueForge provides the agentic infrastructure:

- Agent lifecycle
- Tool orchestration
- Sessions
- Subagents
- Approval checkpoints
- Execution state

ClawForge connects these primitives to ClawNet.

---

## 6. State Model

```text
PLANNING
   ↓
EXECUTING
   ↓
OBSERVING
   ↓
ANALYZING
   ↓
   ├── CONTINUE ──────→ EXECUTING
   │
   └── APPROVAL
          ↓
      APPROVED → EXECUTE
          │
      REJECTED → STOP
```

The **harness owns the state machine**, not the model.

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

TrueForge is officially runnable locally with:
npx @truefoundry/trueforge@latest

It provides the agent loop, tools, sandboxing, approvals, context management, and sessions. GitHub
Official links:
- TrueForge GitHub
- TrueForge npm package
- TrueForge website
And the exact quickstart is:
npx @truefoundry/trueforge@latest

Node.js 22.14+ is currently required.