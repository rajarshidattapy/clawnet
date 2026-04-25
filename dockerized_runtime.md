# PRD — ClawNet Secure Sandbox Execution Layer

## Project Name

**ClawNet Sandbox — Run Before Trust**

## Overview

Every downloaded service, cloned GitHub repo, script, or external project should first run inside a monitored Docker sandbox before touching the local machine.

Instead of directly running unknown code on the host system, ClawNet intercepts it, launches it inside an isolated container, observes its behavior, scores risk, and only allows promotion to the local device if it is safe.

Goal:

## “Nothing runs on the host before ClawNet approves it.”

---

# Core Features + Implementation

---

## 1. Automatic Sandbox Interception

### Feature

Whenever a user:

* clones a GitHub repo
* downloads a project
* installs a new service
* runs an unknown script
* starts an external backend/frontend

ClawNet should redirect execution into a Docker sandbox first.

### Implementation

Create a wrapper command like:

```bash
clawnet run <repo/service>
```

or Git wrapper:

```bash
clawnet clone <github-url>
```

This automatically:

* clones the repo
* creates isolated Docker environment
* installs dependencies
* runs project inside sandbox

Never execute directly on host first.

---

## 2. Dockerized Isolated Runtime

### Feature

Every unknown project runs inside a controlled container.

### Isolation Rules

Restrict:

* host filesystem access
* privileged commands
* unsafe shell execution
* suspicious outbound traffic
* wallet access
* local SSH keys
* browser cookies/session tokens
* local env secrets

### Implementation

Use:

* Docker
* limited permissions
* mounted temp workspace only
* isolated network rules
* resource limits (CPU/RAM)

Optional:

* Firejail / gVisor later

---

## 3. Live Behavioral Monitoring

### Feature

Monitor what the project does while running inside sandbox.

### Detect

* suspicious outbound connections
* hidden crypto miners
* wallet-draining scripts
* malicious install scripts
* secret exfiltration
* environment variable theft
* SSH key access attempts
* unusual package installs
* persistence attempts

### Implementation

Use:

* existing ClawNet monitoring engine
* OpenClaw intelligence layer
* process + network inspection
* file access monitoring

Risk score updates live.

---

## 4. AI Risk Analysis

### Feature

OpenClaw explains if the service is safe or suspicious.

### Example

```text id="2ykavv"
This repo attempts outbound requests
to unknown foreign IPs and reads SSH config files.

Risk Score: HIGH
Recommendation: Do not promote to host.
```

### Implementation

Use:

* OpenClaw analysis
* SuperMemory lookup
* prior known malicious behavior detection

Not just alerts — reasoning.

---

## 5. Safe Promotion to Host

### Feature

Only after validation should the service move to the local machine.

### Outcomes

* SAFE → allow install locally
* SUSPICIOUS → approval required
* DANGEROUS → block execution

### Implementation

Approval flow:

```text id="jpxbz7"
Sandbox Run
↓
Behavior Analysis
↓
Risk Score
↓
Approve / Deny
↓
Promote to Host
```

User must explicitly approve.

---

## 6. Telegram Sandbox Alerts

### Feature

If suspicious behavior is found inside sandbox, send Telegram alerts immediately.

### Example

```text id="6tr8a5"
🚨 Sandbox Alert

Cloned repo attempted access to:
~/.ssh/config

Suspicious outbound traffic detected.

Risk Score: 91
Recommendation: Block promotion
```

### Implementation

Use:

* Telegram Bot API
* approval workflow from Telegram

Remote decision support.

---

## 7. Sandbox Memory + Reputation

### Feature

Remember previously analyzed repos and services.

If the same repo/package appears again:

* skip repeated deep scan
* use prior trust score
* faster decision making

### Implementation

Store:

* Git repo history
* package reputation
* prior suspicious behavior
* previous approvals/rejections

Use SuperMemory engine.

---

# Tech Stack

## Sandbox Layer

* Docker
* Docker SDK for Python

## Monitoring Core

* Python
* psutil
* subprocess
* network inspection

## AI Layer

* OpenClaw

## Memory Layer

* PostgreSQL
* Redis

## Alerts

* Telegram Bot API

## Safety Layer

* send2trash
* policy engine

---

# Final Goal

From:

## “I cloned a repo and hope it’s safe”

To:

## “Every unknown project proves it is safe before touching my machine.”
