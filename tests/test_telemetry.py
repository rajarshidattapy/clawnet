"""Tracing and metrics (core/telemetry.py), their capture points, and the /settings dashboard."""
import json
import time
from types import SimpleNamespace

import pytest
import requests
from rich.console import Console

import clawforge  # noqa: F401  (puts core/ on sys.path)
import llm
import telemetry
from clawforge import harness, monitor


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("TELEMETRY_PATH", str(tmp_path / "traces.jsonl"))
    monkeypatch.setenv("CLAWNET_LLM_CACHE_PATH", str(tmp_path / "cache.json"))
    monkeypatch.setattr(telemetry, "PRICES_PATH", tmp_path / "prices.json")
    for v in ("TELEMETRY", "TELEMETRY_CAPTURE_IO", "TELEMETRY_MAX_MB", "LLM_CACHE", "LLM_PROVIDER", "LLM_MODEL",
              "LLM_API_KEY", "OLLAMA", "OPENROUTER_API_KEY", "OPENAI_MODEL", "OPENAI_BASE_URL"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "k")


def spans():
    return [r for r in telemetry.load() if r["type"] == "span"]


# ── spans ─────────────────────────────────────────────────────────────────────

def test_nested_spans_share_a_trace_and_keep_their_parent():
    with telemetry.span("root", "agent", session="s1", user={"sub": "u", "role": "viewer"}, tags=["t"]) as root:
        with telemetry.span("child", "tool") as child:
            with telemetry.span("grandchild", "generation"):
                pass
    by = {s["name"]: s for s in spans()}
    assert by["root"]["parent"] is None and by["child"]["parent"] == root.span_id
    assert by["grandchild"]["parent"] == child.span_id
    assert len({s["trace"] for s in by.values()}) == 1
    assert by["grandchild"]["session"] == "s1" and by["grandchild"]["user"]["sub"] == "u"      # inherited
    assert by["grandchild"]["tags"] == ["t"] and by["root"]["ms"] >= 0
    with telemetry.span("other", new_trace=True):
        pass
    assert spans()[-1]["trace"] != root.trace_id and telemetry.current() is None


def test_an_exception_marks_the_span_and_propagates():
    with pytest.raises(ValueError):
        with telemetry.span("boom", "tool"):
            raise ValueError("bad pid")
    s = spans()[0]
    assert s["status"] == "error" and s["error"] == "ValueError: bad pid"


def test_io_is_redacted_clipped_and_can_be_switched_off(monkeypatch):
    with telemetry.span("io") as s:
        s.set_io(input="key sk-proj-abcdefghijklmnopqrstuvwxyz123456 mail bob@corp.com", output="x" * 2000)
    rec = spans()[0]
    assert "sk-proj" not in rec["input"] and "bob@corp.com" not in rec["input"] and "[REDACTED:" in rec["input"]
    assert len(rec["output"]) < 700 and "+1400 chars" in rec["output"]
    monkeypatch.setenv("TELEMETRY_CAPTURE_IO", "no")
    with telemetry.span("noio") as s:
        s.set_io(input="secret prompt", output="secret answer")
    assert "input" not in spans()[-1] and "output" not in spans()[-1]


def test_disabled_telemetry_writes_nothing_and_never_raises(monkeypatch, tmp_path):
    monkeypatch.setenv("TELEMETRY", "no")
    with telemetry.span("x") as s:
        s.set(a=1)
    telemetry.score("q", 1)
    assert not telemetry.path().exists()
    monkeypatch.setenv("TELEMETRY", "yes")
    monkeypatch.setenv("TELEMETRY_PATH", str(tmp_path))          # a directory: cannot be opened as a file
    with telemetry.span("still fine"):
        pass                                                        # the write fails silently


def test_record_scores_and_events():
    t0 = time.time()
    with telemetry.span("root", "agent") as root:
        telemetry.record("approval.kill", "human", t0, t0 + 4.5, status="refused", attrs={"approved": False})
        telemetry.score("faithfulness", 4.0, comment="ok")
        root.event("turn.done", tokens=10)
    recs = telemetry.load()
    appr = next(r for r in recs if r.get("name") == "approval.kill")
    assert appr["ms"] == 4500 and appr["status"] == "refused" and appr["parent"] == root.span_id
    sc = next(r for r in recs if r["type"] == "score")
    assert (sc["name"], sc["value"], sc["trace"]) == ("faithfulness", 4.0, root.trace_id)
    assert next(r for r in recs if r.get("name") == "root")["events"][0]["name"] == "turn.done"


def test_log_rolls_over_and_tolerates_a_torn_line(monkeypatch):
    monkeypatch.setenv("TELEMETRY_MAX_MB", "0")
    for i in range(3):
        with telemetry.span(f"s{i}"):
            pass
    assert telemetry.path().with_name("traces.jsonl.1").exists()
    with open(telemetry.path(), "a", encoding="utf-8") as f:
        f.write('{"type": "span", "trace": "torn')                  # a half-written line
    assert all(r["type"] == "span" for r in telemetry.load())
    assert telemetry.clear() >= 1 and telemetry.load() == []


# ── tokens and cost ───────────────────────────────────────────────────────────

def test_cost_uses_the_provider_figure_then_the_price_table_and_never_guesses():
    assert telemetry.cost_usd("openrouter", "m", 1000, 1000, reported=0.0123) == 0.0123
    assert telemetry.cost_usd("ollama", "llama3.1", 5000, 5000) == 0.0
    assert telemetry.cost_usd("openrouter", "vendor/model:free", 5000, 5000) == 0.0
    assert telemetry.cost_usd("openai", "gpt-x", 1000, 1000) is None                    # no price: unpriced, not guessed
    telemetry.set_price("gpt-x", 2.0, 10.0)
    assert telemetry.cost_usd("openai", "gpt-x", 1_000_000, 500_000) == pytest.approx(7.0)


def test_a_price_added_later_covers_calls_already_recorded():
    with telemetry.span("llm", "generation") as s:
        s.set_generation(provider="openai", model="gpt-x", input_tokens=1_000_000, output_tokens=0)
    assert telemetry.summary(telemetry.load())["llm"]["unpriced"] == 1
    telemetry.set_price("gpt-x", 3.0, 0.0)
    llm_m = telemetry.summary(telemetry.load())["llm"]
    assert llm_m["unpriced"] == 0 and llm_m["cost"] == pytest.approx(3.0)


def _post(monkeypatch, responder):
    calls = []
    monkeypatch.setattr(requests, "post", lambda url, **kw: calls.append((url, kw)) or responder(url, kw))
    return calls


class Resp:
    def __init__(self, body=None, ok=True):
        self.body, self.ok = body or {}, ok

    def raise_for_status(self):
        if not self.ok:
            raise requests.HTTPError("503 Service Unavailable")

    def json(self):
        return self.body


def test_every_llm_call_is_a_generation_span_with_tokens_cost_and_latency(monkeypatch):
    body = {"choices": [{"message": {"content": "mail bob@corp.com"}}],
            "usage": {"prompt_tokens": 120, "completion_tokens": 8, "cost": 0.0004}}
    _post(monkeypatch, lambda url, kw: Resp(body))
    assert llm.chat("system prompt", "user text") == "mail [REDACTED:email]"
    s = spans()[0]
    assert (s["name"], s["kind"], s["provider"], s["model"]) == ("llm.chat", "generation", "openai", "gpt-5.4-mini")
    assert s["usage"] == {"input": 120, "output": 8, "total": 128, "estimated": False} and s["cost"] == 0.0004
    assert s["ms"] >= 0 and s["attrs"]["prompt_hash"] and s["attrs"]["redactions"] == 1
    assert s["attrs"]["attempts"][0]["ok"] is True and s["output"] == "mail [REDACTED:email]"


def test_missing_usage_is_estimated_and_flagged(monkeypatch):
    _post(monkeypatch, lambda url, kw: Resp({"choices": [{"message": {"content": "a" * 80}}]}))
    llm.chat("s" * 40, "u" * 40)
    s = spans()[0]
    assert s["usage"]["estimated"] is True and s["usage"]["input"] == 20 and s["usage"]["output"] == 20


def test_anthropic_usage_fields_are_understood(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("LLM_API_KEY", "a")
    _post(monkeypatch, lambda url, kw: Resp({"content": [{"type": "text", "text": "hi"}],
                                             "usage": {"input_tokens": 50, "output_tokens": 3}}))
    llm.chat("s", "u")
    assert spans()[0]["usage"]["input"] == 50 and spans()[0]["provider"] == "anthropic"


def test_cache_hits_fallbacks_and_failures_are_visible(monkeypatch):
    ok = {"choices": [{"message": {"content": "answer"}}], "usage": {"prompt_tokens": 10, "completion_tokens": 2}}
    monkeypatch.setenv("OPENROUTER_API_KEY", "or")
    calls = _post(monkeypatch, lambda url, kw: Resp(ok, ok=("openrouter" in url)))
    llm.chat("s", "u")                                          # OpenAI fails (503), OpenRouter answers
    first = spans()[0]
    assert first["attrs"]["fallback"] is True and first["provider"] == "openrouter"
    assert [(a["provider"], a["ok"]) for a in first["attrs"]["attempts"]] == [("openai", False), ("openrouter", True)]
    assert "503" in first["attrs"]["attempts"][0]["error"]
    llm.chat("s", "u")                                          # the same prompt: answered from the cache
    hit = spans()[1]
    assert hit["attrs"]["cached"] is True and hit["usage"]["total"] == 0 and hit["cost"] == 0.0
    assert len(calls) == 2                                      # no further provider call
    monkeypatch.delenv("OPENROUTER_API_KEY")
    _post(monkeypatch, lambda url, kw: Resp(ok=False))
    with pytest.raises(requests.HTTPError):
        llm.chat("s", "different")
    assert spans()[-1]["status"] == "error"


# ── metrics ───────────────────────────────────────────────────────────────────

def _gen(model, provider, ms, inp, out, status="ok", cached=False):
    t0 = time.time()
    s = telemetry.record("llm.chat", "generation", t0, t0 + ms / 1000, status=status, provider=provider, model=model,
                         input_tokens=inp, output_tokens=out, reported_cost=0.001 * (inp + out) / 1000,
                         attrs={"cached": cached} if cached else None)
    return s


def test_percentiles():
    assert telemetry.percentile([], 95) == 0.0 and telemetry.percentile([7], 50) == 7
    assert telemetry.percentile([1, 2, 3, 4], 50) == 2.5
    assert telemetry.percentile(list(range(1, 101)), 95) == pytest.approx(95.05)


def test_summary_splits_by_model_tool_and_caller():
    for ms in (100, 200, 300, 400):
        _gen("gpt-5.4-mini", "openai", ms, 1000, 100)
    _gen("gpt-5.4-mini", "openai", 5, 0, 0, cached=True)
    _gen("claude-haiku-5-5", "anthropic", 900, 500, 50, status="error")
    t0 = time.time()
    user = {"sub": "rita", "role": "responder", "auth": "jwt"}
    with telemetry.span("tool.kill_process", "tool", user=user):
        pass
    with telemetry.span("tool.kill_process", "tool", user=user) as s:
        s.set_status("refused", "schema")
    telemetry.record("approval.kill_process", "human", t0, t0 + 8)
    m = telemetry.summary(telemetry.load())
    gpt = m["models"]["openai/gpt-5.4-mini"]
    assert gpt["calls"] == 5 and gpt["cached"] == 1 and gpt["input"] == 4000 and gpt["latency"]["p50"] == pytest.approx(250, abs=1)
    assert m["models"]["anthropic/claude-haiku-5-5"]["errors"] == 1
    assert m["llm"]["calls"] == 6 and m["llm"]["cache_hit_rate"] == pytest.approx(1 / 6, abs=1e-3)
    assert m["tool_stats"]["kill_process"]["calls"] == 2 and m["tool_stats"]["kill_process"]["refused"] == 1
    assert m["human"]["approvals"] == 1 and m["human"]["latency"]["avg"] == pytest.approx(8000, abs=5)
    assert m["errors"] == 1 and m["users"] == {"rita (responder)": 2}
    assert len(m["days"]) == 1 and m["llm"]["cost"] > 0
    assert telemetry.summary(telemetry.load(), since=time.time() + 60)["spans"] == 0         # the period filter


def test_trace_listing_and_lookup():
    with telemetry.span("agent.run", "agent", session="sess") as root:
        _gen("m", "p", 50, 100, 10)
        with pytest.raises(RuntimeError):
            with telemetry.span("tool.x", "tool"):
                raise RuntimeError("x")
    with telemetry.span("ok.run", "agent"):
        pass
    rows = telemetry.traces(telemetry.load())
    assert {r["name"]: r["status"] for r in rows} == {"agent.run": "error", "ok.run": "ok"}
    assert [r["name"] for r in telemetry.traces(telemetry.load(), only_errors=True)] == ["agent.run"]
    row = next(r for r in rows if r["name"] == "agent.run")
    assert row["spans"] == 3 and row["tokens"] == 110 and row["session"] == "sess"
    found, _ = telemetry.find_trace(telemetry.load(), root.trace_id[:6])
    assert len(found) == 3
    assert telemetry.find_trace(telemetry.load(), "")[0] == []                       # ambiguous prefix
    assert telemetry.find_trace(telemetry.load(), "zzzz") == ([], [])


# ── the agent's spans ─────────────────────────────────────────────────────────

def test_agent_messages_become_generation_spans():
    t0 = time.time()
    msg = SimpleNamespace(type="model.message", model="openrouter/nvidia-nemotron-free", content="done", thread_id="main",
                          tool_calls=[1, 2], usage=SimpleNamespace(input_tokens=900, output_tokens=40))
    done = SimpleNamespace(type="turn.done")
    with telemetry.span("agent.run", "agent", new_trace=True):
        harness._record_generations([(t0, msg), (t0 + 2.0, done)])
    s = next(r for r in spans() if r["name"] == "agent.llm")
    assert (s["provider"], s["model"]) == ("openrouter", "nvidia-nemotron-free")
    assert s["usage"]["total"] == 940 and s["ms"] == pytest.approx(2000, abs=5) and s["attrs"]["tool_calls"] == 2


# ── the /settings dashboard ───────────────────────────────────────────────────

def _render(renderable) -> str:
    console = Console(width=140, record=True, force_terminal=False)
    console.print(renderable)
    return console.export_text()


def test_dashboard_empty_state_points_at_what_to_do():
    out = _render(monitor.settings(""))
    assert "No spans" in out and "Settings" in out and "telemetry" in out


def test_dashboard_shows_metrics_models_tools_and_traces():
    with telemetry.span("agent.run", "agent", new_trace=True, session="sess-1") as root:
        _gen("gpt-5.4-mini", "openai", 120, 2000, 100)
        _gen("gpt-x", "openai", 300, 1000, 10, status="error")
        with telemetry.span("tool.kill_process", "tool", user={"sub": "rita", "role": "responder", "auth": "jwt"}):
            pass
    telemetry.score("faithfulness", 5)
    out = _render(monitor.settings("24h"))
    for expected in ("Monitoring · last 24h", "openai/gpt-5.4-mini", "kill_process", "agent.run", "faithfulness",
                     "rita (responder)", "errors", "p95", "Per day", "Recent traces"):
        assert expected in out, expected
    assert "agent.run" in _render(monitor.settings("traces")) and "Errors" in _render(monitor.settings("errors"))
    assert "openai/gpt-x" in _render(monitor.settings("models")) and "kill_process" in _render(monitor.settings("tools"))
    assert "sess-1" in _render(monitor.settings("sessions"))
    tree = _render(monitor.settings(f"trace {root.trace_id[:8]}"))
    assert "llm.chat" in tree and "openai/gpt-5.4-mini" in tree
    assert "tool.kill_process" in tree and "waterfall" in tree and "rita (responder)" in tree
    assert "No single trace" in _render(monitor.settings("trace nope"))


def test_trace_view_shows_attempts_cache_hits_and_io(monkeypatch):
    ok = {"choices": [{"message": {"content": "an answer"}}], "usage": {"prompt_tokens": 10, "completion_tokens": 2}}
    monkeypatch.setenv("OPENROUTER_API_KEY", "or")
    _post(monkeypatch, lambda url, kw: Resp(ok, ok=("openrouter" in url)))
    with telemetry.span("agent.run", "agent", new_trace=True) as root:
        llm.chat("s", "the prompt")
    out = _render(monitor.settings(f"trace {root.trace_id[:8]}"))
    for expected in ("attempt openai/gpt-5.4-mini", "attempt openrouter/", "fell back", "the prompt", "an answer", "503"):
        assert expected in out, expected


def test_settings_can_be_changed_but_only_the_safe_ones(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("OPENAI_API_KEY=sk-keep-me\nOLLAMA=no\n# TELEMETRY=yes\nOTHER=1\n", encoding="utf-8")
    monkeypatch.setattr(monitor, "ENV_PATH", str(env))
    assert "OLLAMA=yes" in monitor.set_setting("ollama", "YES", str(env)) and "/setup" in monitor.set_setting("OLLAMA", "yes", str(env))
    assert monitor.set_setting("TELEMETRY", "no", str(env)).startswith("[green]")
    lines = env.read_text(encoding="utf-8").splitlines()
    assert lines[:2] == ["OPENAI_API_KEY=sk-keep-me", "OLLAMA=yes"] and "OTHER=1" in lines and "TELEMETRY=no" in lines
    assert llm.ollama_enabled() and not telemetry.enabled()          # applied to this process
    monkeypatch.delenv("OLLAMA"), monkeypatch.delenv("TELEMETRY")
    for key, value in (("LLM_API_KEY", "sk-x"), ("OPENAI_API_KEY", "sk-x"), ("CLAWFORGE_TOKEN", "x")):
        assert "Not a setting" in monitor.set_setting(key, value, str(env))           # secrets are not settable here
    assert "not valid" in monitor.set_setting("LLM_PROVIDER", "bogus", str(env))
    assert "not valid" in monitor.set_setting("OLLAMA", "maybe", str(env))
    assert env.read_text(encoding="utf-8").count("sk-x") == 0


def test_price_command_changes_the_dashboard():
    _gen("gpt-x", "openai", 10, 1000, 0)
    t = telemetry.set_price  # noqa: F841
    with telemetry.span("u", "generation") as s:
        s.set_generation(provider="openai", model="gpt-unpriced", input_tokens=1_000_000, output_tokens=0)
    assert "unpriced" in _render(monitor.settings("models"))
    assert "priced gpt-unpriced" in _render(monitor.settings("price gpt-unpriced 2.5 10"))
    assert "$2.5" in _render(monitor.settings("models"))
    assert "Usage" in _render(monitor.settings("price oops"))
