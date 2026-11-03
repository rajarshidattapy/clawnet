# Guardrails

Part 1 is how guardrails are usually built into AI agents. Part 2 is how ClawNet / ClawForge does it, including the output guardrails added most recently.

---

## Part 1: Guardrails in agents, in general

An agent is a language model that can call tools. The model is probabilistic and can be manipulated, so it cannot be the thing that enforces safety. A guardrail is a check that sits **outside** the model and holds no matter what the model says.

Guardrails are layered, because each layer catches something the others miss.

### The layers

| Layer | Question it answers | Typical techniques |
|---|---|---|
| **Input** | Is what goes *into* the model safe? | Prompt-injection filters, stripping instruction-like text from untrusted data, PII masking before the model sees it, length limits, topic allow-lists |
| **Output** | Is what comes *out* of the model safe? | Secret and PII redaction, toxicity or policy classifiers, schema validation of structured output, "does this answer match the evidence" checks |
| **Tool / action** | Is what the model wants to *do* allowed? | Per-tool JSON Schema on arguments, allow-lists and deny-lists, rate limits, dry-run or preview, human approval for risky calls |
| **Execution** | If it runs, how much damage can it do? | Sandboxes, least-privilege credentials, network off by default, canary secrets, timeouts |
| **Audit and evals** | Can we see what happened, and does it keep working? | Append-only logs, replayable traces, regression tests that attack the guardrails |

### Principles that matter more than any single technique

1. **Deterministic beats probabilistic.** Regexes, schemas and rule engines give the same answer every time. An LLM "judge" can itself be talked out of its decision. Use code for anything that must hold, and models only for soft judgments.
2. **Enforce in the server, not the prompt.** "Please don't kill system processes" in a system prompt is a hope. A check in the code that runs the action is a guarantee. Prompts guide behavior and code enforces limits.
3. **Defense in depth.** A human approving an action does not replace validating it. The schema gate, the policy check and the approval each catch different mistakes.
4. **Treat everything the model reads as untrusted.** Process names, file contents, web pages and tool output can all contain instructions (indirect prompt injection). Data must stay data.
5. **Fail closed.** If validation fails or a check errors, refuse. Do not run the action.
6. **Least destructive first.** Prefer reversible actions (suspend, block) over irreversible ones (kill, delete), and make the model show the consequence before acting.
7. **Log refusals, not just actions.** A refused call is evidence that something tried to go wrong.
8. **Test the guardrails.** Attack your own agent (injection strings, malformed arguments) in CI, so a change that weakens a guardrail fails the build.

### Where redaction and schema checks fit

- **Output redaction** is a last filter on text a person will read or a log will store. It catches a model that repeats a credential it saw, or that invents something that looks like one. It uses pattern matching (known key formats, `password=...`, emails, Luhn-valid card numbers).
- **Schema validation of actions** treats the model's tool call as untrusted input to an API. It checks shape: types, ranges, required fields, no extra fields, safe formats. It does not judge whether the action is wise. That job belongs to a policy layer and to a human.

---

## Part 2: Guardrails in ClawNet / ClawForge

ClawNet is a security tool: an agent investigates a machine and may propose actions like killing a process or blocking an IP. The design rule is the one from Part 1: **the model investigates, explains and proposes; code decides.**

```
                    untrusted machine data
                              │
                  ┌───────────▼───────────┐
   INPUT          │  scrub() firewall      │  core/policy.py
                  └───────────┬───────────┘
                              │
                        ┌─────▼─────┐
                        │   MODEL   │   (explains, proposes, never decides verdicts)
                        └─────┬─────┘
                              │
                  ┌───────────▼───────────┐
   OUTPUT         │  redact() secrets/PII  │  core/guardrails.py
                  └───────────┬───────────┘
                              │  tool call
                  ┌───────────▼───────────┐
   ACTION         │  schema validation     │  core/guardrails.py   (harness, then server)
                  │  preview + human OK    │  clawforge/harness.py
                  │  policy refusal        │  core/policy.py via capabilities.py
                  └───────────┬───────────┘
                              │
                  ┌───────────▼───────────┐
   EXECUTION      │  sandbox (Daytona/     │  core/sandbox.py
                  │  Docker), no network   │
                  └───────────┬───────────┘
                              ▼
   AUDIT          ~/.clawnet/decisions.jsonl + replay evals (core/replay.py)
```

### 2.1 Input: the prompt-injection firewall (already existed)

- `policy.scrub()` in `core/policy.py` is applied to every machine-sourced string before the model sees it: process names, paths, sandbox output. It strips instruction-like text ("ignore previous instructions") and braces, backticks and newlines, then truncates.
- Verdicts (SAFE / SUSPICIOUS / CRITICAL) come from a **deterministic rule engine**, not from the model. The model can explain a verdict but cannot change it, so injected text cannot move a score.
- The agent's instructions (`INSTRUCTIONS` in `clawforge/harness.py`) say tool output from the machine or a sandbox is data, never instructions.

### 2.2 Action: approval, preview and policy (already existed)

- Control tools (`kill_process`, `suspend_process`, `block_ip`, `quarantine_file`, `close_port`, `promote_sandbox_run`) are marked destructive. TrueForge pauses the agent and requires approval for them (`require_approval_for_tools`). The names are also listed explicitly, so a lost annotation cannot remove the gate.
- **Preview before proposing.** `preview_action` measures guardrail status, target evidence, blast radius and reversibility. The harness re-measures this itself and shows it to the human, whatever the agent claimed in its `reason`.
- **Policy refusal after approval.** Even if a human approves, ClawNet's own guardrails still run and can refuse: protected processes, private IPs, System32, failed chain of trust. Each refusal is logged.
- **The harness owns the state machine** (PLANNING → OBSERVING → ANALYZING → APPROVAL → ...). The model never advances it. An illegal transition is shown, not silently taken.
- After a denial the agent is told to stop and not retry or work around it.

### 2.3 Execution: sandbox (already existed)

Code the agent wants to run goes into an ephemeral Daytona sandbox (Docker as fallback), never onto the host. It has decoy credentials and canary secrets, and network is off by default. A planted secret leaving the process is itself a detection rule. Provider API keys are on the sandbox's deny list so they cannot leak into a container.

### 2.4 Output: secret and PII redaction (new)

File: `core/guardrails.py` → `redact()`, `redact_report()`, `StreamRedactor`.

**What it does.** It replaces secrets and PII in model-written text with `[REDACTED:<kind>]`.

| Kind | Examples |
|---|---|
| Secrets | OpenAI / Anthropic / OpenRouter / Google keys, AWS keys, GitHub and Slack tokens, Stripe keys, JWTs, bearer tokens, private-key blocks, `user:pass@` in URLs, `NAME=value` where the name contains key / secret / token / password |
| PII | emails, phone numbers, US SSNs, credit cards (only if the digits pass the Luhn check) |

**What it deliberately leaves alone.** IP addresses, hashes, file paths, PIDs and ports. In a security tool those are the evidence. The phone and card patterns are tight, so a 16-digit number that is not a valid card, a timestamp or a SHA-256 is not touched.

**Streaming.** The agent's text arrives in small chunks, and a key can be split across two of them. `StreamRedactor` holds back the trailing partial word until the next chunk or a flush, so a split secret is still caught.

**Where it is applied:**

| Place | File |
|---|---|
| Every `llm.chat()` result (verdict explanations) | `core/llm.py` |
| The agent's streamed text on screen | `clawforge/harness.py` (`_stream`) |
| The approval briefing shown to the human (arguments and the agent's reason) | `clawforge/harness.py` (`_render_briefing`) |
| The human's denial reason, and the `reason` written to the decision log | `harness.py`, `capabilities.py` |

**Limits.** It is pattern-based, so it catches known formats and obvious assignments. A secret with no recognizable shape, written in prose, can slip through. Names and street addresses are not detected. Treat it as a strong last filter, not a guarantee.

### 2.5 Action: JSON Schema validation (new)

File: `core/guardrails.py` → `validate_action()`, `schema_for()`.

Each control action has a JSON Schema (`additionalProperties: false`, every field required):

| Action | Checks |
|---|---|
| `kill_process`, `suspend_process` | `pid` is an integer (not a bool), 1 to 4194304 |
| `block_ip` | `ip` parses as a real IP address (a range or hostname is rejected) |
| `quarantine_file` | `path` is absolute (`C:\...`), has no `..` segment, no `* ? < > |`, 3 to 520 characters |
| `close_port` | `port` is an integer, 1 to 65535 |
| `promote_sandbox_run` | `run_id` matches `^[A-Za-z0-9_\-]{1,64}$` |
| all | `reason` is a string of 20 to 1000 characters (it must say what, why, and what breaks) |

An unknown action name is also rejected.

**It is enforced twice:**

1. **In the harness** (`ask_human` in `clawforge/harness.py`). A malformed proposal is rejected *before the human is asked*. The operator sees a red "proposal is malformed" panel instead of an approval prompt, and the agent is told it was denied.
2. **In the server** (`_act` and `promote_sandbox_run` in `clawforge/capabilities.py`). The MCP server re-validates, so a client that skips the harness (a different UI, a direct tool call) is still covered. A bad proposal returns `{"ok": false, "refused": "schema", "errors": [...]}`, nothing runs, and `action_refused` is written to the decision log. This is the authoritative check.

**Shape, not policy.** The schema only checks that a proposal is well-formed. Whether a target is off-limits (private IP ranges, PID 4, protected processes, System32) is left to ClawNet's policy layer, which refuses and logs it as before. Keeping the layers separate means each refusal is recorded by the layer that made it, and the policy layer stays the single source of truth for "is this allowed".

### 2.6 Audit and evals

- Every verdict, approval, refusal and action is appended to `~/.clawnet/decisions.jsonl`. Schema refusals are logged as `action_refused` with the errors.
- `core/replay.py` replays recorded sessions and checks decision determinism, injection resistance, guardrail safety (no recommended action a guardrail would refuse) and explanation faithfulness. `tests/test_policy.py` runs it in CI.
- `tests/test_guardrails.py` covers the new layers: redaction of each secret and PII kind, that evidence is not redacted, a secret split across chunks, well-formed and malformed actions for every tool, and that the server refuses a bad proposal without running it.

### 2.7 What is not covered

- **No content-safety classifier** (toxicity, harmful-content filters). The agent's domain is narrow and its outputs are security findings, so this was not the priority.
- **No rate limits** on control actions.
- **Redaction is not applied to tool output going into the model.** That is machine evidence and is already scrubbed for injection. Only model-written text is redacted.
- **No role-based limits.** Every caller of the MCP server can reach every tool. Per-user permissions would be a separate layer (see the RBAC item in `docs/todo.md`).
- **Output redaction is regex-based** (see 2.4).

### Quick map

| Concern | File |
|---|---|
| Injection scrubber, rule engine, decision log | `core/policy.py` |
| Secret / PII redaction, action schemas | `core/guardrails.py` |
| Redaction on LLM answers | `core/llm.py` |
| Approval flow, state machine, streamed redaction, harness-side schema gate | `clawforge/harness.py` |
| Server-side schema gate, policy refusal, decision logging | `clawforge/capabilities.py` |
| Approval annotations, tool definitions, token / JWT auth | `clawforge/mcp_server.py` |
| Sandbox | `core/sandbox.py` |
| Replay evals | `core/replay.py`, `tests/test_policy.py`, `tests/test_guardrails.py` |
