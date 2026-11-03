"""Tracing and metrics for ClawNet / ClawForge. Our own, stdlib only, no external service.

What it records (the same ideas an LLM-observability platform gives you):

  traces      a request end to end: a tree of spans (agent session -> model calls, tool calls,
              human approvals). Each span has start/end, status, latency and attributes.
  generations spans of kind "generation": provider, model, prompt hash, token usage, cost,
              latency, cache hit, which attempts were made (fallback), time and error.
  sessions    spans carry a session id, so a whole conversation can be listed and summed.
  users       spans carry the caller (JWT subject / role), so usage can be split by who.
  tags, I/O   free tags, plus the input and output of each span (redacted and truncated).
  scores      numeric quality scores attached to a trace (the quality evals write them).
  metrics     request counts, error rate, p50/p95/p99 latency, tokens and cost, by model,
              tool, day and caller. Computed from the spans, so nothing can drift.

Storage: an append-only JSONL file, ~/.clawnet/traces.jsonl, shared by every ClawNet process
(the console, the MCP server). Telemetry never raises into the app: a failure to record is
dropped. Prompts and answers are already scrubbed/redacted upstream; they are redacted again
here, and `TELEMETRY_CAPTURE_IO=no` stores no text at all.

    TELEMETRY=yes|no              default yes
    TELEMETRY_CAPTURE_IO=yes|no   default yes (stored text is redacted, cut to 600 characters)
    TELEMETRY_PATH                default ~/.clawnet/traces.jsonl
    TELEMETRY_MAX_MB              default 50; the file rolls over to traces.jsonl.1 past this

Cost: a provider-reported cost is used when the provider sends one (OpenRouter does). Otherwise
tokens x the price table in ~/.clawnet/prices.json ({"model-id": {"input": usd_per_million,
"output": usd_per_million}}, edit it or use `/settings price`). Local (Ollama) and `:free`
models cost 0. No built-in prices are shipped: a model with no price is reported as unpriced,
never guessed.
"""
from __future__ import annotations

import contextvars
import json
import os
import secrets
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

try:
    from guardrails import redact
except ImportError:
    from core.guardrails import redact  # type: ignore

_DEFAULT_PATH = Path.home() / ".clawnet" / "traces.jsonl"
PRICES_PATH = Path.home() / ".clawnet" / "prices.json"
_LOCK = threading.Lock()
_CURRENT: contextvars.ContextVar = contextvars.ContextVar("clawnet_span", default=None)
_IO_LIMIT = 600
_TAIL_BYTES = 12 * 1024 * 1024        # how much of the file the dashboard reads


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, "").strip() or default


def _yes(name: str, default: str) -> bool:
    return _env(name, default).lower() in ("1", "true", "yes", "y", "on")


def enabled() -> bool:
    return _yes("TELEMETRY", "yes")


def capture_io() -> bool:
    return _yes("TELEMETRY_CAPTURE_IO", "yes")


def path() -> Path:
    return Path(_env("TELEMETRY_PATH", str(_DEFAULT_PATH)))


def _new_id(nbytes: int) -> str:
    return secrets.token_hex(nbytes)


# ── cost ──────────────────────────────────────────────────────────────────────

def load_prices() -> dict:
    try:
        data = json.loads(PRICES_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def set_price(model: str, input_per_mtok: float, output_per_mtok: float) -> None:
    prices = load_prices()
    prices[model] = {"input": float(input_per_mtok), "output": float(output_per_mtok)}
    PRICES_PATH.parent.mkdir(parents=True, exist_ok=True)
    PRICES_PATH.write_text(json.dumps(prices, indent=2, sort_keys=True), encoding="utf-8")


def cost_usd(provider: str, model: str, input_tokens: int, output_tokens: int,
             reported: Optional[float] = None) -> Optional[float]:
    """The cost of one call in USD, or None when it cannot be priced (never a guess)."""
    if reported is not None:
        return float(reported)
    if provider == "ollama" or (model or "").endswith(":free"):
        return 0.0
    price = load_prices().get(model) or load_prices().get(f"{provider}/{model}")
    if not isinstance(price, dict):
        return None
    return (input_tokens * float(price.get("input", 0)) + output_tokens * float(price.get("output", 0))) / 1e6


def estimate_tokens(text: str) -> int:
    """A rough count (4 characters a token) for providers that report no usage."""
    return max(1, len(text or "") // 4) if text else 0


# ── spans ─────────────────────────────────────────────────────────────────────

class Span:
    def __init__(self, name: str, kind: str, parent: "Optional[Span]", attrs: dict,
                 session: Optional[str], user: Optional[dict], tags: Optional[list]) -> None:
        self.name, self.kind = name, kind
        self.trace_id = parent.trace_id if parent else _new_id(8)
        self.span_id = _new_id(4)
        self.parent_id = parent.span_id if parent else None
        self.session = session or (parent.session if parent else None)
        self.user = user or (parent.user if parent else None)
        self.tags = list(tags or []) or (list(parent.tags) if parent else [])
        self.start = time.time()
        self.end: Optional[float] = None
        self.status, self.error = "ok", ""
        self.attrs: dict[str, Any] = dict(attrs)
        self.input = self.output = None
        self.usage: Optional[dict] = None
        self.model = self.provider = None
        self.cost: Optional[float] = None
        self.events: list[dict] = []

    # -- what instrumented code calls ------------------------------------------
    def set(self, **attrs: Any) -> "Span":
        self.attrs.update(attrs)
        return self

    def set_status(self, status: str, error: str = "") -> "Span":
        self.status, self.error = status, error[:300]
        return self

    def set_io(self, input: Any = None, output: Any = None) -> "Span":
        if capture_io():
            if input is not None:
                self.input = _clip(input)
            if output is not None:
                self.output = _clip(output)
        return self

    def set_generation(self, *, provider: str, model: str, input_tokens: int = 0, output_tokens: int = 0,
                       estimated: bool = False, reported_cost: Optional[float] = None) -> "Span":
        self.provider, self.model = provider, model
        self.usage = {"input": int(input_tokens), "output": int(output_tokens),
                      "total": int(input_tokens) + int(output_tokens), "estimated": estimated}
        self.cost = cost_usd(provider, model, int(input_tokens), int(output_tokens), reported_cost)
        return self

    def event(self, name: str, **attrs: Any) -> None:
        self.events.append({"t": round(time.time() - self.start, 4), "name": name, **attrs})

    # -- serialisation ---------------------------------------------------------
    def to_record(self) -> dict:
        end = self.end if self.end is not None else time.time()
        rec: dict[str, Any] = {
            "type": "span", "trace": self.trace_id, "span": self.span_id, "parent": self.parent_id,
            "name": self.name, "kind": self.kind, "start": round(self.start, 4),
            "ms": round((end - self.start) * 1000, 2), "status": self.status,
        }
        for key, value in (("error", self.error), ("session", self.session), ("user", self.user),
                           ("tags", self.tags), ("input", self.input), ("output", self.output),
                           ("usage", self.usage), ("model", self.model), ("provider", self.provider),
                           ("attrs", self.attrs), ("events", self.events)):
            if value:
                rec[key] = value
        if self.usage is not None:
            rec["cost"] = self.cost         # None = unpriced; kept so the dashboard can count it
        return rec


def _clip(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
    text = redact(text)
    return text if len(text) <= _IO_LIMIT else text[:_IO_LIMIT] + f"… (+{len(text) - _IO_LIMIT} chars)"


def current() -> Optional[Span]:
    return _CURRENT.get()


@contextmanager
def span(name: str, kind: str = "span", *, new_trace: bool = False, session: Optional[str] = None,
         user: Optional[dict] = None, tags: Optional[list] = None, **attrs: Any) -> Iterator[Span]:
    """Time a block as a span. Nested calls become child spans of the same trace.

    An exception marks the span `error` and is re-raised untouched. kind: agent | generation |
    tool | human | eval | span.
    """
    parent = None if new_trace else _CURRENT.get()
    s = Span(name, kind, parent, attrs, session, user, tags)
    token = _CURRENT.set(s)
    try:
        yield s
    except BaseException as exc:
        if s.status == "ok":
            s.set_status("error", f"{type(exc).__name__}: {exc}")
        raise
    finally:
        _CURRENT.reset(token)
        s.end = time.time()
        _write(s.to_record())


def record(name: str, kind: str, start: float, end: float, *, status: str = "ok", error: str = "",
           session: Optional[str] = None, **fields: Any) -> Optional[Span]:
    """Record a span that already happened (times known after the fact), under the current span.

    fields: any of input, output, model, provider, input_tokens, output_tokens, reported_cost,
    attrs (dict).
    """
    s = Span(name, kind, _CURRENT.get(), fields.pop("attrs", None) or {}, session, None, None)
    s.start, s.end = start, end
    s.set_status(status, error)
    s.set_io(fields.pop("input", None), fields.pop("output", None))
    if "model" in fields or "input_tokens" in fields:
        s.set_generation(provider=fields.get("provider") or "", model=fields.get("model") or "",
                         input_tokens=fields.get("input_tokens", 0), output_tokens=fields.get("output_tokens", 0),
                         reported_cost=fields.get("reported_cost"))
    _write(s.to_record())
    return s


def score(name: str, value: float, *, trace_id: Optional[str] = None, comment: str = "") -> None:
    """Attach a numeric score (an eval result, a user rating) to a trace."""
    cur = _CURRENT.get()
    tid = trace_id or (cur.trace_id if cur else None)
    _write({"type": "score", "trace": tid, "name": name, "value": value,
            "comment": comment[:200], "ts": round(time.time(), 4)})


# ── storage ───────────────────────────────────────────────────────────────────

def _write(record: dict) -> None:
    if not enabled():
        return
    try:
        p = path()
        line = json.dumps(record, default=str, ensure_ascii=False) + "\n"
        with _LOCK:
            p.parent.mkdir(parents=True, exist_ok=True)
            try:
                if p.stat().st_size > int(_env("TELEMETRY_MAX_MB", "50")) * 1024 * 1024:
                    os.replace(p, p.with_name(p.name + ".1"))
            except OSError:
                pass
            with open(p, "a", encoding="utf-8") as f:
                f.write(line)
    except Exception:
        pass        # telemetry must never break the app


def load(max_bytes: int = _TAIL_BYTES) -> list[dict]:
    """Records from the end of the log (spans and scores), oldest first."""
    p = path()
    try:
        size = p.stat().st_size
        with open(p, "rb") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
                f.readline()                    # drop a partial first line
            raw = f.read().decode("utf-8", "replace")
    except OSError:
        return []
    out = []
    for line in raw.splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def clear() -> int:
    """Delete the log. Returns how many records it held."""
    n = len(load())
    for p in (path(), path().with_name(path().name + ".1")):
        try:
            p.unlink()
        except OSError:
            pass
    return n


# ── metrics ───────────────────────────────────────────────────────────────────

def percentile(values: list, pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * pct / 100
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def _latency(ms: list) -> dict:
    return {"avg": round(sum(ms) / len(ms), 1) if ms else 0.0, "p50": round(percentile(ms, 50), 1),
            "p95": round(percentile(ms, 95), 1), "p99": round(percentile(ms, 99), 1),
            "max": round(max(ms), 1) if ms else 0.0}


def effective_cost(s: dict) -> Optional[float]:
    """A span's cost: the one recorded with it, else priced now from the price table (so a price
    added later also covers calls already recorded). None = still unpriced."""
    if s.get("cost") is not None or not s.get("usage"):
        return s.get("cost")
    return cost_usd(s.get("provider") or "", s.get("model") or "", s["usage"]["input"], s["usage"]["output"])


def _tokens_and_cost(spans: list) -> dict:
    gens = [s for s in spans if s.get("usage")]
    costs = [c for c in (effective_cost(s) for s in gens) if c is not None]
    return {"input": sum(s["usage"]["input"] for s in gens), "output": sum(s["usage"]["output"] for s in gens),
            "total": sum(s["usage"]["total"] for s in gens),
            "cost": round(sum(costs), 6), "priced": len(costs), "unpriced": len(gens) - len(costs)}


def summary(records: list[dict], since: Optional[float] = None) -> dict:
    """Dashboard metrics over spans started at or after `since` (epoch seconds)."""
    spans = [r for r in records if r.get("type") == "span" and (since is None or r["start"] >= since)]
    scores = [r for r in records if r.get("type") == "score" and (since is None or r.get("ts", 0) >= since)]
    llm = [s for s in spans if s["kind"] == "generation"]
    tools = [s for s in spans if s["kind"] == "tool"]
    errors = [s for s in spans if s["status"] == "error"]

    by_model: dict[str, list] = {}
    for s in llm:
        by_model.setdefault(f"{s.get('provider') or '?'}/{s.get('model') or '?'}", []).append(s)
    models = {}
    for key, group in by_model.items():
        live = [s for s in group if not (s.get("attrs") or {}).get("cached")]
        models[key] = {"calls": len(group), "cached": len(group) - len(live),
                       "errors": sum(s["status"] == "error" for s in group),
                       **_tokens_and_cost(group), "latency": _latency([s["ms"] for s in live])}

    by_tool: dict[str, list] = {}
    for s in tools:
        by_tool.setdefault(s["name"].removeprefix("tool."), []).append(s)
    tool_stats = {n: {"calls": len(g), "errors": sum(s["status"] == "error" for s in g),
                      "refused": sum(s["status"] == "refused" for s in g),
                      "latency": _latency([s["ms"] for s in g])} for n, g in by_tool.items()}

    days: dict[str, dict] = {}
    for s in llm:
        d = time.strftime("%Y-%m-%d", time.localtime(s["start"]))
        day = days.setdefault(d, {"calls": 0, "tokens": 0, "cost": 0.0})
        day["calls"] += 1
        day["tokens"] += (s.get("usage") or {}).get("total", 0)
        day["cost"] = round(day["cost"] + (effective_cost(s) or 0.0), 6)

    users: dict[str, int] = {}
    for s in spans:
        if s.get("user") and s["kind"] in ("tool", "generation", "agent"):
            label = f"{s['user'].get('sub')} ({s['user'].get('role')})"
            users[label] = users.get(label, 0) + 1

    cached = sum(1 for s in llm if (s.get("attrs") or {}).get("cached"))
    return {
        "spans": len(spans), "traces": len({s["trace"] for s in spans}),
        "sessions": len({s["session"] for s in spans if s.get("session")}),
        "errors": len(errors), "error_rate": round(len(errors) / len(spans), 4) if spans else 0.0,
        "llm": {"calls": len(llm), "cached": cached, "cache_hit_rate": round(cached / len(llm), 4) if llm else 0.0,
                "latency": _latency([s["ms"] for s in llm if not (s.get("attrs") or {}).get("cached")]),
                **_tokens_and_cost(llm)},
        "tools": {"calls": len(tools), "refused": sum(s["status"] == "refused" for s in tools),
                  "latency": _latency([s["ms"] for s in tools])},
        "human": {"approvals": sum(1 for s in spans if s["kind"] == "human"),
                  "latency": _latency([s["ms"] for s in spans if s["kind"] == "human"])},
        "models": models, "tool_stats": tool_stats, "days": dict(sorted(days.items())),
        "users": users,
        "scores": {n: round(sum(r["value"] for r in scores if r["name"] == n) /
                            max(1, sum(1 for r in scores if r["name"] == n)), 3)
                   for n in {r["name"] for r in scores}},
    }


def traces(records: list[dict], since: Optional[float] = None, limit: int = 20, only_errors: bool = False) -> list[dict]:
    """One row per trace (newest first): name of the root span, duration, spans, tokens, cost."""
    spans = [r for r in records if r.get("type") == "span" and (since is None or r["start"] >= since)]
    by_trace: dict[str, list] = {}
    for s in spans:
        by_trace.setdefault(s["trace"], []).append(s)
    rows = []
    for tid, group in by_trace.items():
        root = next((s for s in group if not s.get("parent")), None) or min(group, key=lambda s: s["start"])
        tc = _tokens_and_cost(group)
        row = {"trace": tid, "name": root["name"], "kind": root["kind"], "start": root["start"],
               "ms": max(s["start"] * 1000 + s["ms"] for s in group) - min(s["start"] * 1000 for s in group),
               "spans": len(group), "status": "error" if any(s["status"] == "error" for s in group) else root["status"],
               "session": root.get("session"), "user": root.get("user"), "tokens": tc["total"], "cost": tc["cost"],
               "unpriced": tc["unpriced"]}
        if not only_errors or row["status"] == "error":
            rows.append(row)
    rows.sort(key=lambda r: r["start"], reverse=True)
    return rows[:limit]


def find_trace(records: list[dict], prefix: str) -> tuple[list[dict], list[dict]]:
    """(spans, scores) of the trace whose id starts with `prefix`; ([], []) when none or ambiguous."""
    ids = {r["trace"] for r in records if r.get("type") == "span" and r["trace"].startswith(prefix)}
    if len(ids) != 1:
        return [], []
    tid = ids.pop()
    return ([r for r in records if r.get("type") == "span" and r["trace"] == tid],
            [r for r in records if r.get("type") == "score" and r.get("trace") == tid])
