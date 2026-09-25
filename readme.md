# ClawForge

### From terminal → agentic harness.

**ClawForge is an open-source harness for running, observing, and controlling agentic workloads on your machine.**

It evolves from a security-focused terminal into a layer that an internal agentic system can operate through, powered by [TrueForge](https://github.com/truefoundry/trueforge).

---

## The Problem

Modern agents can **write and execute code**, but there is a missing layer between the agent and the machine.

You need somewhere to:

- Run untrusted or generated code safely.
- See what processes that code starts.
- See which ports and network connections it opens.
- Understand what is actually happening on the machine.
- Decide whether a process or connection is suspicious.
- Let an agent investigate the system instead of blindly executing commands.
- Stop before an action can cause real damage.

Most existing tooling solves only one piece of this.

You have terminals that execute commands, sandboxes that isolate code, and system monitors that show processes or connections — but there is no simple, open-source **agentic layer that brings these capabilities together**.

---

## What is ClawForge?

ClawForge provides that layer.

```text
                    ⚡ CLAWFORGE
                  Agentic Harness
                         │
                  ┌──────▼──────┐
                  │  TrueForge  │
                  │             │
                  │ Agents      │
                  │ Sessions    │
                  │ Subagents   │
                  │ Approvals   │
                  └──────┬──────┘
                         │
                  ┌──────▼──────┐
                  │   ClawNet   │
                  │             │
                  │ Sandbox     │
                  │ Processes   │
                  │ Network     │
                  │ Policy      │
                  │ Actions     │
                  └──────┬──────┘
                         │
                         ▼
                      Machine
```

### ClawForge lets an agent:

**Run**

Execute code inside an isolated environment rather than directly on the host.

**Observe**

Inspect processes, ports, connections, filesystem activity, and execution behavior.

**Reason**

Ask questions such as:

> *Which processes currently running on my machine look suspicious?*

> *What opened this connection?*

> *Which process is listening on this port?*

> *What did this code actually do when executed?*

**Control**

Take actions through ClawNet's policy and security layer.

**Stop**

Pause before sensitive or irreversible actions and require human approval.

---

## Architecture

ClawForge is not a separate agent platform sitting beside ClawNet.

**ClawNet is becoming the harness.**

TrueForge provides the agentic orchestration primitives, while ClawNet provides the machine-level capabilities and security boundaries.

```text
Agent
  │
  ▼
TrueForge
  │
  ├── Sessions
  ├── Subagents
  ├── Tool orchestration
  └── Approval checkpoints
  │
  ▼
ClawNet
  │
  ├── Network monitoring
  ├── Process inspection
  ├── Sandbox execution
  ├── Policy engine
  ├── Behavioral analysis
  └── Security actions
  │
  ▼
Machine
```

The agent **does not directly control the machine**.

---

## Run TrueForge

```bash
npx @truefoundry/trueforge@latest
```

- [TrueForge](https://github.com/truefoundry/trueforge)
- [ClawNet](https://github.com/rajarshidattapy/clawnet)

---

## The Idea

```text
Traditional

Terminal → Machine


ClawForge

Agent
  ↓
Harness
  ↓
Observe → Execute → Analyze → Control
  ↓
Machine
```

> **The agent reasons.  
> TrueForge orchestrates.  
> ClawNet observes and enforces.  
> The machine executes.**

## Files

1) core/              -> core logic
2) scripts/           -> scripts to run for setup
3) tests/             -> feature tests
4) docs/clawnet_docs/ -> old security terminal
5) new_arch.md        -> updated idea to build on
5) hackdetails.md     -> details about the hackathon
6) trueforge_integration -> check if needed


Built for the **TrueFoundry TrueForge Hackathon**.