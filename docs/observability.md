# Observability

Part 1 is what LLM observability usually covers. Part 2 is what ClawNet records, how, and how to read it in the console with `/settings`. It is our own implementation (`core/telemetry.py`): standard library only, no external service, nothing sent off the machine.

---

## Part 1: Observability for agents, in general

An agent makes many model and tool calls per request, and each one can be slow, expensive or wrong. Logs alone do not show which call was the slow one, what it cost, or how the pieces fit together. LLM-observability platforms (Langfuse and similar) solve this with a few ideas:

| Idea | What it is | Why it matters |
|---|---|---|
| **Trace** | One request end to end | "Why did this answer take 40 seconds?" |
| **Span** | One step inside a trace, with a parent, start, end, status | Shows where the time went; a tree, not a flat log |
| **Generation** | A span that is a model call: provider, model, prompt version, tokens, cost | The unit of cost and quality |
| **Session** | A group of traces from one conversation | Cost and behavior per conversation |
| **User / caller** | Who triggered it | Usage and cost per person or service |
| **Tags and metadata** | Free labels | Filtering ("eval runs", "production") |
| **Input / output** | What went in and came out, per span | Debugging a bad answer |
| **Scores** | A number attached to a trace (eval result, user rating) | Puts quality next to cost and latency |
| **Metrics** | Aggregates: request count, error rate, p50/p95/p99 latency, tokens, cost by model, day, caller | The dashboard |
| **Human-in-the-loop time** | How long a person took to approve | A real part of latency for agents with approval gates |

Things that go wrong if done carelessly:

- **Storing secrets.** Prompts and answers can hold credentials and personal data. Redact before storing, and let users turn input/output capture off.
- **Guessing costs.** Prices change and differ by provider. Use the provider's reported cost when there is one, otherwise a price table you control, and show "unpriced" instead of a made-up number.
- **Breaking the app.** Telemetry must never raise into the code it observes.
- **Unbounded growth.** Rotate or cap the log.

---

## Part 2: Observability in ClawNet / ClawForge

### What is recorded

`core/telemetry.py` records **spans** into an append-only file, `~/.clawnet/traces.jsonl`, shared by every ClawNet process (the console and the MCP server). A span is wrapped around:

| Where | Span name | Kind | What it captures |
|---|---|---|---|
| `llm.chat()` (`core/llm.py`) | `llm.chat` | generation | provider, model, prompt hash, tokens in/out, cost, latency, cache hit, redaction count, every provider attempt (so a fallback is visible), error |
| every MCP tool (`clawforge/mcp_server.py`) | `tool.<name>` | tool | tier, caller (subject, role, auth method), latency, status: `ok`, `refused` (RBAC or schema) or `error`, input and output |
| the agent session (`clawforge/harness.py`) | `agent.run` | agent | the task, session id; the root of the trace |
| each model message from the agent | `agent.llm` | generation | model, tokens as reported by TrueForge, latency |
| each tool call as the agent saw it | `call.<name>` | toolcall | end-to-end latency including the network |
| each human approval | `approval.<name>` | human | how long the person took, and whether they approved |
| quality evals (`core/quality.py`) | `eval.<case>` | eval | the generator and judge calls nest under it; the scores are attached |

`tool` spans (server side) feed the Tools table. `toolcall` spans (agent side) are only shown inside trace trees, so a call is never counted twice.

Each span also carries: trace id, span id, parent, start, duration in ms, status, session, caller, tags, events, and (unless turned off) redacted input and output.

**Scores.** `telemetry.score(name, value)` attaches a number to the current trace. The quality evals write faithfulness, grounding, clarity and a pass flag, so quality sits next to tokens, cost and latency of the same run.

### Tokens and cost

- **Tokens** come from the provider's response (OpenAI-style `prompt_tokens`/`completion_tokens`, Anthropic `input_tokens`/`output_tokens`). If a provider reports none, the count is estimated at about 4 characters per token and the span is flagged `estimated`.
- **Cost**, in this order:
  1. the cost the provider reports (OpenRouter sends one);
  2. `0` for local Ollama and for `:free` models;
  3. tokens × your price table, `~/.clawnet/prices.json`: `{"model-id": {"input": usd_per_million, "output": usd_per_million}}`;
  4. otherwise **unpriced**. No prices are built in, because they change and a wrong default would make the numbers untrustworthy.
- Set a price from the console: `/settings price <model> <input_per_mtok> <output_per_mtok>`. A price added later also covers calls already recorded.
- A cache hit costs `0` and shows as a call with `cached`.

### Safety of what is stored

- Input and output text is redacted again (secrets and PII, `core/guardrails.py`) and cut to 600 characters. Prompts are already scrubbed upstream.
- `TELEMETRY_CAPTURE_IO=no` stores no text at all, only timings, tokens and statuses.
- `TELEMETRY=no` turns recording off entirely.
- A failure to write never reaches the application.
- The file rolls over to `traces.jsonl.1` past `TELEMETRY_MAX_MB` (default 50), and the dashboard reads only the last 12 MB.

### The `/settings` dashboard

In the console (`python -m clawforge`):

| Command | Shows |
|---|---|
| `/settings` | the overview for the last 24 hours |
| `/settings 1h` · `7d` · `30d` · `all` | the same for another period |
| `/settings live [period]` | the overview, refreshing every 2 seconds (`q`, Esc or Ctrl+C to leave) |
| `/settings traces [n]` · `errors` | the latest traces, or only the failing ones |
| `/settings trace <id>` | one trace as a tree with a latency waterfall, per-span tokens and cost, provider attempts, redaction counts, input/output, and its scores (an id prefix is enough) |
| `/settings models` · `tools` | the per-model and per-tool tables |
| `/settings sessions` | one row per agent session |
| `/settings set KEY VALUE` | change a setting, saved to `.env` and applied now |
| `/settings price MODEL IN OUT` | set a model's price for cost |
| `/settings clear` | delete the trace log (asks first) |
| `/settings help` | this list |

**The overview** has:

- **Requests**: traces, sessions, spans, error count and rate.
- **Model latency**: p50, p95, p99, max, call count and cache hit rate.
- **Tokens**: total, in, out, per call.
- **Cost**: total, and how many calls were priced or unpriced.
- **Tools**: calls, refused, latency.
- **Human approvals**: count and average and p95 wait.
- **Eval scores**: the mean of each recorded score.
- **Callers**: the busiest callers and their roles.
- **Models** table: calls, cached, errors, tokens in/out, cost, p50, p95 per `provider/model`.
- **Tools** table: calls, errors, refused, average and p95 latency per tool.
- **Per day**: a bar per day for the last 7 days, with tokens, calls and cost.
- **Recent traces** and the **Settings** panel.

**Settings you can change** from the console (non-secret switches only; keys and tokens cannot be set this way): `OLLAMA`, `LLM_PROVIDER`, `LLM_MODEL`, `OLLAMA_MODEL`, `LLM_CACHE`, `TELEMETRY`, `TELEMETRY_CAPTURE_IO`. A change rewrites only that line of `.env`. Changing `OLLAMA`, `LLM_PROVIDER` or a model also needs `/setup` so the TrueForge agent switches too; the console says so.

### Metrics, exactly

Computed from the spans each time, so they cannot drift from the data:

- error rate = spans with status `error` ÷ spans (a `refused` call is a guardrail doing its job, so it is counted separately and is not an error);
- latency percentiles use linear interpolation, over live calls only (cache hits are excluded so they do not drag p50 toward zero);
- cache hit rate = generation spans with `cached` ÷ generation spans.

### Limits

- **Agent-side model latency is approximate.** TrueForge does not report per-message timing, so an `agent.llm` span runs from when the message first arrived to when the next event did. Tokens come from TrueForge and are exact. The explain calls from `core/llm.py` are timed exactly.
- **MCP tool spans are separate traces.** TrueForge does not forward a trace id to the MCP server, so a server-side `tool.<name>` span is not nested under the agent's `agent.run`. They are linked by time and by the agent's own `call.<name>` span.
- **No built-in prices.** Until you add them, models without a provider-reported cost show as unpriced.
- **Local and single-host.** One shared file, no remote collector, no multi-machine view, no alerting.
- **Scoped to ClawNet.** It does not see model calls TrueForge makes outside a ClawForge session.

### Where it lives

| Concern | File |
|---|---|
| Spans, storage, cost, metrics | `core/telemetry.py` |
| Model-call spans and usage parsing | `core/llm.py` |
| Tool spans | `clawforge/mcp_server.py` (`tool()` wrapper) |
| Agent, tool-call and approval spans | `clawforge/harness.py` |
| Eval scores | `core/quality.py` |
| `/settings` dashboard and switches | `clawforge/monitor.py`, wired in `clawforge/tui.py` |
| Tests | `tests/test_telemetry.py`, `tests/test_rbac.py` (tool spans) |
