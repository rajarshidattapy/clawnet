# Volo

> **Deterministic testing for AI agents — in CI, at ~$0.** Record your agent run once, replay it
> against a high-fidelity simulated environment that never hallucinates, and block reliability
> regressions in your pull requests. Like unit tests and `git bisect`, but for agents.

Most agent "evals" re-run a live LLM-as-judge on every check — which costs API money *and is
itself non-deterministic*. Volo flips that: it **replays a recorded run deterministically against
mocked tools**, so the same PR check gives the same answer every time, for free.

---

## Why

Teams ship AI agents that fail non-deterministically and can't be tested like normal software.
Going from "80% works in a pilot" to "99%+ in production" can take 100× the original build
effort. Today's tools either trace agents *after* they fail in production or run shallow
benchmarks that don't reflect reality.

Volo makes agents testable the way regular software is testable:

1. **Record** a real run once — every model call, tool call, and decision.
2. **Simulate** the agent's full environment — not just cache-replay, but a stateful,
   source-informed simulator that handles inputs you never recorded (and flags, never
   hallucinates, when it can't).
3. **Generate adversarial scenarios** automatically: dropped tool results, ambiguous turns,
   prompt injection, long-horizon drift.
4. **Measure reliability** across orthogonal dimensions: trajectory determinism, decision
   determinism, faithfulness, consistency-under-repetition.
5. **Block regressions in CI** — every PR runs the suite deterministically at $0 marginal cost.
6. **Root-cause and diff** — "git bisect for agents" pinpoints the breaking step and the commit.

## Quickstart (local)

> Requires: `uv ≥ 0.5`, Node ≥ 20 with `corepack` enabled.

```bash
git clone https://github.com/abhay-codes07/VOLO.git
cd VOLO
make setup        # installs Python (uv) + JS toolchains, syncs deps
uv run volo --help

# fastest end-to-end try — record an example agent and score it in one step:
uv run volo init examples.calc_agent:run --input '{"a":2,"b":3,"c":4}'
```

A minimal record → replay loop on a bundled example:

```bash
uv run volo record examples.echo_agent:run --out ./.volo/recordings/echo.json
uv run volo sim ./.volo/recordings/echo.json     # deterministic replay, $0
```

Score an agent against the adversarial scenario suite and get a ship / no-ship verdict:

```bash
uv run volo run ./.volo/recordings/echo.json --agent examples.echo_agent:run
```

### Optional: a free LLM judge

Faithfulness can be scored by a local heuristic (default, free, deterministic), local Ollama, or
a free OpenAI-compatible API (Groq by default). Drop a key in `.env` (copy `.env.example`):

```env
VOLO_OPENAI_COMPAT_OPT_IN=true
GROQ_API_KEY=gsk_...
```

```bash
uv run volo run <recording> --agent <module:fn> --judge groq
```

## Or just write pytest tests

`pytest-volo` puts the whole engine behind ordinary fixtures — one marker binds a recording,
`volo_scenario` parametrizes the test over every adversarial world, and `volo_run` returns the
ship/no-ship verdict:

```python
import pytest
from pytest_volo import assert_ship

@pytest.mark.volo_recording("recordings/checkout.json")
def test_survives_adversity(volo_scenario):      # runs once per hostile world
    assert run_my_agent({"order": 42})["status"] in ("ok", "refused")

@pytest.mark.volo_recording("recordings/checkout.json")
def test_ships(volo_run):
    assert_ship(volo_run(run_my_agent, n_runs=3))
```

## Deterministic tests for your MCP stack

Volo can record and replay **Model Context Protocol servers** — so agents that depend on MCP
tools get deterministic integration tests with no network, no credentials, and no API cost.

Put the recording proxy between any MCP client and the real server once:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"add","arguments":{"a":2,"b":40}}}' \
| uv run volo mcp record --out calc.json -- python examples/mcp_calc_server.py
```

From then on, replay the recording as a **simulated MCP server** — byte-identical answers,
fully offline:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add","arguments":{"a":2,"b":40}}}' \
| uv run volo mcp serve calc.json
# {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"42"}],"isError":false}}
```

Replay matches on the *tool name + arguments* (not request ids), recorded protocol errors replay
as errors, and anything un-recorded returns JSON-RPC error `-32042` — the simulator **never
invents a tool result**. Recorded `tools/list` responses are auto-distilled into tool schemas,
so the Tier-2 simulator can take over for near-miss inputs. Full guide: `volo mcp --help` or the
[docs site](website/).

## Does the simulator make things up? No — it flags.

The hard part of replaying against a *simulated* environment is inputs you never recorded. Volo
either reconstructs them faithfully (from tool specs/sources) or **refuses and flags** — it never
fabricates a tool result. Measured on a held-out benchmark (deterministic, reproducible):

| Configuration | Fidelity | Wrong answers |
|---|---|---|
| Tier-1 only (cache replay) | 20% | **0** |
| Tier-2 (source-informed) | **100%** | **0** |

`Wrong = 0` in every configuration is the whole point — see [`benchmarks/`](benchmarks/) and run
`uv run python benchmarks/fidelity.py` yourself.

## Architecture

The core subsystems behind a CLI and a Next.js dashboard:

```
Capture SDK → Environment Simulator → Scenario Generator → Reliability Engine
       ↓                                                            ↓
    CI Runner ───────── Root-Cause / Diff ─────────────── Cost-Routing Brain
```

## The full pipeline (v5.0)

One recorded run flows through every gate — deterministic, offline, ~$0 — and comes out the other
side as a signed credential:

```
record → simulate → scenarios → reliability → red-team safety → CERTIFY → evidence pack → cloud
                                     │              │               │            │
                          ship/no-ship verdict   safe?        Volo Certified   EU AI Act /
                                                              (signed badge)   ISO 42001 / SOC 2
```

Beyond the core testing loop, Volo now spans: **MCP** and **computer-use** record/replay,
**multi-agent** system verdicts, **red-team** safety, **personas** & **long-horizon** simulation,
a **marketplace** of signed scenario packs + a **leaderboard**, **compliance evidence packs**,
**Volo Certified** (a signed pass/fail credential), a **VS Code** extension, and a commercial
**cloud control plane** (teams / RBAC / SSO / hosted sim-minutes) — all OSS-core, Apache-2.0, with
the paid plane isolated in `cloud/`.

## Repo layout

```
packages/       # Python packages (uv workspace) — core, sdk, simulator, scenarios, reliability,
                #   runner, diff, models, cli, mcp, redteam, personas, horizon, packs, compliance,
                #   computeruse, multiagent, certify, …
services/api/   # FastAPI backend (local dashboard + cloud seam)
apps/web/       # Next.js dashboard      apps/vscode/  # VS Code extension
cloud/          # commercial control plane (teams / RBAC / SSO / sim-minutes) — separate license
integrations/   # framework adapters: langgraph, openai_agents, crewai, autogen, …
examples/       # runnable demo agents (also the CI dogfood targets)
tests/          # cross-package integration, e2e (incl. the v5.0 full-pipeline test), benchmarks
```

## Tech stack

Python 3.12+ (uv workspace), FastAPI, SQLModel + SQLite, Ollama for local judging, and a free
OpenAI-compatible provider for optional LLM judging. Frontend is Next.js + TypeScript + Tailwind.
Everything runs fully locally with zero cloud accounts.

## License

Open-core. The entire OSS product is **Apache-2.0** (see [`LICENSE`](LICENSE)); the commercial
control plane under [`cloud/`](cloud/) is separately licensed (see [`cloud/LICENSE`](cloud/LICENSE)).