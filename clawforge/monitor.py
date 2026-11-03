"""/settings: the monitoring dashboard and settings of the ClawForge console.

Reads the spans core/telemetry.py records (every model call, tool call and human approval)
and shows them as metrics, tables and trace trees. Nothing here talks to a server.

    /settings                      overview for the last 24h: requests, latency, tokens, cost,
                                   models, tools, days, recent traces, config
    /settings 1h|24h|7d|30d|all    same, for another period
    /settings live [period]        the overview, refreshing every 2 s (q or Ctrl+C to leave)
    /settings traces [n]           the latest traces          /settings errors   failing ones
    /settings trace <id>           one trace as a tree with a latency waterfall, I/O and scores
    /settings models | tools       the per-model / per-tool tables
    /settings sessions             one row per agent session
    /settings route fast|reasoning MODEL  choose a model for that workload (saved to .env)
    /settings set KEY VALUE        change a setting (saved to .env, applied now)
    /settings price MODEL IN OUT   dollars per million input / output tokens, for cost
    /settings clear                delete the trace log
"""
from __future__ import annotations

import os
import time
from typing import Optional

import clawforge
import llm
import llm_cache
import telemetry
from clawforge import rbac

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

HELP = (__doc__ or "").split("\n\n", 1)[-1].strip("\n")        # the command list in the docstring above

PERIODS = {"1h": 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "all": None}
DEFAULT_PERIOD = "24h"
ENV_PATH = os.path.join(os.path.dirname(clawforge.CORE_DIR), ".env")

YES_NO = lambda v: v.lower() in ("yes", "no", "true", "false", "1", "0", "on", "off")      # noqa: E731
SETTINGS = {         # key -> (what it is, validator). Only non-secret switches can be set here.
    "OLLAMA": ("yes = local model only, no cloud call", YES_NO),
    "LLM_PROVIDER": ("openai | anthropic | gemini | openrouter", lambda v: v.lower() in llm.PROVIDERS),
    "LLM_MODEL": ("model id for the chosen provider", lambda v: 0 < len(v) <= 100 and " " not in v),
    "LLM_FAST_MODEL": ("small/fast model for short explanations", lambda v: 0 < len(v) <= 100 and " " not in v),
    "LLM_REASONING_MODEL": ("larger model for copilot and agent work", lambda v: 0 < len(v) <= 100 and " " not in v),
    "OLLAMA_MODEL": ("local model, e.g. llama3.1", lambda v: 0 < len(v) <= 100 and " " not in v),
    "LLM_CACHE": ("cache answers by prompt hash", YES_NO),
    "TELEMETRY": ("record traces and metrics", YES_NO),
    "TELEMETRY_CAPTURE_IO": ("store redacted prompts and answers in traces", YES_NO),
}
_NEEDS_SETUP = {"OLLAMA", "LLM_PROVIDER", "LLM_MODEL", "LLM_FAST_MODEL", "LLM_REASONING_MODEL", "OLLAMA_MODEL"}


# ── formatting ────────────────────────────────────────────────────────────────

def _ms(v: float) -> str:
    return "—" if not v else "<1ms" if v < 1 else (f"{v:.0f}ms" if v < 1000 else f"{v / 1000:.1f}s" if v < 60000 else f"{v / 60000:.1f}min")


def _tok(v: int) -> str:
    return f"{v:,}" if v < 10000 else f"{v / 1000:.1f}k" if v < 1_000_000 else f"{v / 1_000_000:.2f}M"


def _usd(v: float, unpriced: int = 0) -> str:
    text = f"${v:.4f}" if v < 1 else f"${v:,.2f}"
    return text + (f" +{unpriced} unpriced" if unpriced else "")


def _pct(v: float) -> str:
    return f"{v * 100:.1f}%"


def _ago(ts: float) -> str:
    d = time.time() - ts
    return f"{d:.0f}s ago" if d < 90 else f"{d / 60:.0f}m ago" if d < 5400 else f"{d / 3600:.0f}h ago" if d < 172800 else f"{d / 86400:.0f}d ago"


_STATUS = {"ok": "green", "error": "red", "refused": "yellow"}
_KIND = {"agent": "bright_cyan", "generation": "magenta", "tool": "cyan", "toolcall": "blue",
         "human": "yellow", "eval": "green"}


def _status(s: str) -> Text:
    return Text(s, style=_STATUS.get(s, "white"))


def _since(period: str) -> Optional[float]:
    secs = PERIODS.get(period)
    return None if secs is None else time.time() - secs


# ── overview ──────────────────────────────────────────────────────────────────

def _kpi(title: str, lines: list) -> Panel:
    return Panel(Group(*[Text.from_markup(l) for l in lines]), title=f"[bold]{title}[/bold]",
                 border_style="bright_black", padding=(0, 1), expand=True)


def overview(records: list, period: str) -> Group:
    m = telemetry.summary(records, _since(period))
    if not m["spans"]:
        return Group(Panel(
            f"[dim]No spans in the last {period}. Ask the agent something, or run /news, and come back.\n"
            f"Telemetry is {'on' if telemetry.enabled() else '[red]OFF[/red] (/settings set TELEMETRY yes)'}. "
            f"Log: {telemetry.path()}[/dim]", title=f"[bold]Monitoring · {period}[/bold]", border_style="bright_black"),
            config_panel())
    llm_m, tools, human = m["llm"], m["tools"], m["human"]
    lat = llm_m["latency"]
    kpis = Table.grid(expand=True, padding=(0, 1))
    for _ in range(4):
        kpis.add_column(ratio=1)
    kpis.add_row(
        _kpi("Requests", [f"traces [bold]{m['traces']}[/bold]   sessions [bold]{m['sessions']}[/bold]",
                          f"spans [bold]{m['spans']}[/bold]",
                          f"errors [{'red' if m['errors'] else 'green'}]{m['errors']}[/] ({_pct(m['error_rate'])})"]),
        _kpi("Model latency", [f"p50 [bold]{_ms(lat['p50'])}[/bold]   p95 [bold]{_ms(lat['p95'])}[/bold]",
                               f"p99 {_ms(lat['p99'])}   max {_ms(lat['max'])}",
                               f"calls {llm_m['calls']}  cached {_pct(llm_m['cache_hit_rate'])}"]),
        _kpi("Tokens", [f"total [bold]{_tok(llm_m['total'])}[/bold]",
                        f"in {_tok(llm_m['input'])}   out {_tok(llm_m['output'])}",
                        f"per call {_tok(llm_m['total'] // llm_m['calls']) if llm_m['calls'] else '—'}"]),
        _kpi("Cost", [f"[bold]{_usd(llm_m['cost'])}[/bold]",
                      f"priced {llm_m['priced']}   unpriced [{'yellow' if llm_m['unpriced'] else 'green'}]{llm_m['unpriced']}[/]",
                      "[dim]/settings price <model> <in> <out>[/dim]" if llm_m["unpriced"] else "[dim]provider-reported or priced[/dim]"]),
    )
    kpis.add_row(
        _kpi("Tools", [f"calls [bold]{tools['calls']}[/bold]   refused [{'yellow' if tools['refused'] else 'green'}]{tools['refused']}[/]",
                       f"p50 {_ms(tools['latency']['p50'])}   p95 {_ms(tools['latency']['p95'])}"]),
        _kpi("Human approvals", [f"decisions [bold]{human['approvals']}[/bold]",
                                 f"avg wait {_ms(human['latency']['avg'])}   p95 {_ms(human['latency']['p95'])}"]),
        _kpi("Eval scores", [f"{n} [bold]{v}[/bold]" for n, v in sorted(m["scores"].items())] or ["[dim]none recorded[/dim]"]),
        _kpi("Callers", [f"{u} [bold]{n}[/bold]" for u, n in sorted(m["users"].items(), key=lambda x: -x[1])[:3]] or ["[dim]no caller data[/dim]"]),
    )
    return Group(
        Panel(kpis, title=f"[bold bright_cyan]Monitoring · last {period}[/bold bright_cyan]", border_style="bright_cyan"),
        models_table(m), tools_table(m), days_panel(m), traces_table(telemetry.traces(records, _since(period), 8)),
        config_panel(),
        Text.from_markup("[dim]/settings traces · trace <id> · models · tools · sessions · errors · live · set · price · clear[/dim]"),
    )


def models_table(m: dict) -> Panel:
    t = Table(box=None, header_style="bold", pad_edge=False)
    for col, right in (("model", False), ("calls", True), ("cached", True), ("err", True), ("in", True),
                       ("out", True), ("cost", True), ("p50", True), ("p95", True)):
        t.add_column(col, justify="right" if right else "left")
    for key, v in sorted(m["models"].items(), key=lambda kv: -kv[1]["calls"]):
        t.add_row(key, str(v["calls"]), str(v["cached"]), Text(str(v["errors"]), style="red" if v["errors"] else ""),
                  _tok(v["input"]), _tok(v["output"]),
                  _usd(v["cost"]) if v["priced"] else Text("unpriced", style="yellow"),
                  _ms(v["latency"]["p50"]), _ms(v["latency"]["p95"]))
    if not m["models"]:
        t.add_row("[dim]no model calls[/dim]")
    return Panel(t, title="[bold]Models[/bold]", border_style="bright_black")


def tools_table(m: dict) -> Panel:
    t = Table(box=None, header_style="bold", pad_edge=False)
    for col, right in (("tool", False), ("calls", True), ("err", True), ("refused", True), ("avg", True), ("p95", True)):
        t.add_column(col, justify="right" if right else "left")
    for name, v in sorted(m["tool_stats"].items(), key=lambda kv: -kv[1]["calls"]):
        t.add_row(name, str(v["calls"]), Text(str(v["errors"]), style="red" if v["errors"] else ""),
                  Text(str(v["refused"]), style="yellow" if v["refused"] else ""),
                  _ms(v["latency"]["avg"]), _ms(v["latency"]["p95"]))
    if not m["tool_stats"]:
        t.add_row("[dim]no tool calls[/dim]")
    return Panel(t, title="[bold]Tools[/bold]", border_style="bright_black")


def days_panel(m: dict) -> Panel:
    days = list(m["days"].items())[-7:]
    if not days:
        return Panel("[dim]no model calls[/dim]", title="[bold]Per day[/bold]", border_style="bright_black")
    top = max(v["tokens"] for _, v in days) or 1
    t = Table.grid(padding=(0, 2))
    for day, v in days:
        bar = "█" * max(1 if v["tokens"] else 0, round(30 * v["tokens"] / top))
        t.add_row(day, Text(bar, style="magenta"), f"{_tok(v['tokens'])} tok", f"{v['calls']} calls", _usd(v["cost"]))
    return Panel(t, title="[bold]Per day[/bold]", border_style="bright_black")


def traces_table(rows: list, title: str = "Recent traces") -> Panel:
    t = Table(box=None, header_style="bold", pad_edge=False)
    for col, right in (("id", False), ("when", False), ("name", False), ("status", False), ("time", True),
                       ("spans", True), ("tokens", True), ("cost", True), ("session", False)):
        t.add_column(col, justify="right" if right else "left")
    for r in rows:
        t.add_row(r["trace"][:8], _ago(r["start"]), Text(r["name"], style=_KIND.get(r["kind"], "")), _status(r["status"]),
                  _ms(r["ms"]), str(r["spans"]), _tok(r["tokens"]) if r["tokens"] else "—",
                  _usd(r["cost"]) if r["tokens"] and not r["unpriced"] else "—", (r["session"] or "—")[:10])
    if not rows:
        t.add_row("[dim]none[/dim]")
    return Panel(t, title=f"[bold]{title}[/bold]", border_style="bright_black")


def config_panel() -> Panel:
    try:
        p = llm.resolve()
        fast, reasoning = llm.routed("fast"), llm.routed("reasoning")
        backup = llm.fallback()
        model = f"{p.name} · {p.model}" + (" (local)" if p.local else "")
        key = "n/a" if p.local else ("set" if p.api_key else "[yellow]missing[/yellow]")
        fb = f"{backup.name} · {backup.model}" if backup else "none"
    except SystemExit as exc:
        model, key, fb, fast, reasoning = f"[red]{exc}[/red]", "?", "?", None, None
    cache = llm_cache.stats()
    size = telemetry.path().stat().st_size if telemetry.path().exists() else 0
    onoff = lambda b: "[green]on[/green]" if b else "[red]off[/red]"      # noqa: E731
    t = Table.grid(padding=(0, 2))
    t.add_row("[bold]LLM[/bold]", model, "key", key, "fallback", fb)
    if fast is not None and reasoning is not None:
        t.add_row("[bold]Routes[/bold]", f"fast: {fast.model}", "reasoning", reasoning.model, "", "")
    t.add_row("[bold]Ollama[/bold]", onoff(llm.ollama_enabled()), "cache", f"{onoff(cache['enabled'])} {cache['entries']} entries",
              "telemetry", f"{onoff(telemetry.enabled())} io {onoff(telemetry.capture_io())} {size / 1024:.0f} KB")
    t.add_row("[bold]Access[/bold]", f"service token = {rbac.service_role()}", "", "", "prices", f"{len(telemetry.load_prices())} set")
    t.add_row("", "[dim]/settings route fast|reasoning MODEL[/dim]")
    t.add_row("", "[dim]/settings set OLLAMA yes|no · LLM_PROVIDER · LLM_MODEL · LLM_CACHE · TELEMETRY · TELEMETRY_CAPTURE_IO[/dim]")
    return Panel(t, title="[bold]Settings[/bold]", border_style="bright_black")


# ── a single trace ────────────────────────────────────────────────────────────

def trace_view(records: list, prefix: str, show_io: bool = True) -> Panel:
    spans, scores = telemetry.find_trace(records, prefix)
    if not spans:
        return Panel(f"[yellow]No single trace starts with '{prefix}'.[/yellow] Try /settings traces.",
                     border_style="yellow")
    t0 = min(s["start"] for s in spans)
    total = max(s["start"] + s["ms"] / 1000 for s in spans) - t0 or 0.001
    kids: dict = {}
    for s in sorted(spans, key=lambda s: s["start"]):
        kids.setdefault(s.get("parent"), []).append(s)
    ids = {s["span"] for s in spans}
    roots = [s for s in spans if s.get("parent") not in ids]
    t = Table(box=None, header_style="bold", pad_edge=False)
    t.add_column("span", no_wrap=True, min_width=44, overflow="ellipsis")
    t.add_column("status")
    t.add_column("time", justify="right")
    t.add_column("waterfall")
    t.add_column("tokens / cost", justify="right")
    t.add_column("detail", overflow="fold")

    def add(s: dict, depth: int) -> None:
        offset, width = int(24 * (s["start"] - t0) / total), max(1, round(24 * (s["ms"] / 1000) / total))
        bar = " " * offset + "█" * min(width, 24 - offset)
        u = s.get("usage")
        c = telemetry.effective_cost(s)
        tokens = f"{_tok(u['total'])} · {_usd(c) if c is not None else 'unpriced'}" if u else ""
        a = s.get("attrs") or {}
        detail = []
        if s.get("model"):
            detail.append(f"{s.get('provider') or ''}/{s['model']}".strip("/"))
        if a.get("cached"):
            detail.append("cache hit")
        if a.get("fallback"):
            detail.append("fell back")
        if a.get("redactions"):
            detail.append(f"{a['redactions']} redacted")
        if s.get("error"):
            detail.append(s["error"])
        if s.get("user"):
            detail.append(f"{s['user'].get('sub')} ({s['user'].get('role')})")
        t.add_row(Text("  " * depth + s["name"], style=_KIND.get(s["kind"], "")), _status(s["status"]), _ms(s["ms"]),
                  Text(bar, style=_STATUS.get(s["status"], "white")), tokens, " · ".join(detail))
        for att in a.get("attempts") or []:
            t.add_row(Text("  " * (depth + 1) + f"attempt {att.get('provider')}/{att.get('model')}", style="dim"),
                      Text("ok" if att.get("ok") else "error", style="green" if att.get("ok") else "red"),
                      _ms(att.get("ms", 0)), "", "", att.get("error", ""))
        if show_io:
            for label, field in (("in", "input"), ("out", "output")):
                if s.get(field):
                    t.add_row(Text("  " * (depth + 1) + label, style="dim"), "", "", "", "", Text(str(s[field])[:200], style="dim"))
        for child in kids.get(s["span"], []):
            add(child, depth + 1)

    for root in roots:
        add(root, 0)
    parts = [t]
    if scores:
        parts.append(Text.from_markup("[bold]scores[/bold]  " + "   ".join(f"{r['name']} [bold]{r['value']}[/bold]" for r in scores)))
    root = roots[0]
    head = f"trace {root['trace']} · {_ms(total * 1000)} · {len(spans)} spans" + (f" · session {root['session']}" if root.get("session") else "")
    return Panel(Group(*parts), title=f"[bold]{head}[/bold]", border_style="bright_cyan")


def sessions_table(records: list, period: str) -> Panel:
    rows: dict[str, dict] = {}
    for s in records:
        if s.get("type") != "span" or not s.get("session") or (_since(period) and s["start"] < _since(period)):
            continue
        r = rows.setdefault(s["session"], {"first": s["start"], "last": s["start"], "traces": set(), "tokens": 0, "cost": 0.0, "errors": 0})
        r["first"], r["last"] = min(r["first"], s["start"]), max(r["last"], s["start"] + s["ms"] / 1000)
        r["traces"].add(s["trace"])
        r["tokens"] += (s.get("usage") or {}).get("total", 0)
        r["cost"] += telemetry.effective_cost(s) or 0.0
        r["errors"] += s["status"] == "error"
    t = Table(box=None, header_style="bold", pad_edge=False)
    for col, right in (("session", False), ("started", False), ("traces", True), ("tokens", True), ("cost", True), ("errors", True)):
        t.add_column(col, justify="right" if right else "left")
    for sid, r in sorted(rows.items(), key=lambda kv: -kv[1]["last"])[:20]:
        t.add_row(sid[:14], _ago(r["first"]), str(len(r["traces"])), _tok(r["tokens"]), _usd(r["cost"]),
                  Text(str(r["errors"]), style="red" if r["errors"] else ""))
    if not rows:
        t.add_row("[dim]no sessions[/dim]")
    return Panel(t, title=f"[bold]Sessions · {period}[/bold]", border_style="bright_black")


# ── settings ──────────────────────────────────────────────────────────────────

def write_env(key: str, value: str, path: str = ENV_PATH) -> None:
    """Set KEY=value in the .env file, changing only that line (or appending it)."""
    lines = open(path, encoding="utf-8").read().splitlines() if os.path.exists(path) else []
    for i, line in enumerate(lines):
        if line.split("=", 1)[0].strip() == key and "=" in line and not line.lstrip().startswith("#"):
            lines[i] = f"{key}={value}"
            break
    else:
        lines.append(f"{key}={value}")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


def set_setting(key: str, value: str, path: str = ENV_PATH) -> str:
    key = key.upper()
    if key not in SETTINGS:
        return "[yellow]Not a setting you can change here.[/yellow] Settable: " + ", ".join(SETTINGS)
    what, valid = SETTINGS[key]
    if not valid(value):
        return f"[yellow]'{value}' is not valid for {key}[/yellow] ({what})"
    value = value.lower() if key in ("OLLAMA", "LLM_CACHE", "TELEMETRY", "TELEMETRY_CAPTURE_IO", "LLM_PROVIDER") else value
    write_env(key, value, path)
    os.environ[key] = value
    note = ("\n[dim]The TrueForge agent still has the old model. Run /setup to switch it too.[/dim]"
            if key in _NEEDS_SETUP else "")
    return f"[green]{key}={value}[/green] saved to .env and applied.{note}"


def settings(arg: str, records: Optional[list] = None):
    """The renderable for `/settings <arg>`. (`live` and `clear` are handled by the console.)"""
    words = arg.split()
    records = telemetry.load() if records is None else records
    cmd = words[0].lower() if words else ""
    period = next((w for w in words if w.lower() in PERIODS), DEFAULT_PERIOD)
    if cmd in ("", *PERIODS):
        return overview(records, period)
    if cmd in ("traces", "errors"):
        n = next((int(w) for w in words[1:] if w.isdigit()), 20)
        return traces_table(telemetry.traces(records, _since(period), n, only_errors=cmd == "errors"),
                            "Errors" if cmd == "errors" else "Traces")
    if cmd == "trace" and len(words) > 1:
        return trace_view(records, words[1])
    if cmd in ("models", "tools"):
        m = telemetry.summary(records, _since(period))
        return models_table(m) if cmd == "models" else tools_table(m)
    if cmd == "sessions":
        return sessions_table(records, period)
    if cmd == "route":
        route_keys = {"fast": "LLM_FAST_MODEL", "reasoning": "LLM_REASONING_MODEL"}
        if len(words) != 3 or words[1].lower() not in route_keys:
            return Text.from_markup("Usage: /settings route fast|reasoning MODEL")
        return Text.from_markup(set_setting(route_keys[words[1].lower()], words[2]))
    if cmd == "set":
        if len(words) < 3:
            return Text.from_markup("Usage: /settings set KEY VALUE. Settable: " + ", ".join(f"{k} ({v[0]})" for k, v in SETTINGS.items()))
        return Text.from_markup(set_setting(words[1], words[2]))
    if cmd == "price":
        try:
            model, inp, out = words[1], float(words[2]), float(words[3])
        except (IndexError, ValueError):
            return Text.from_markup("Usage: /settings price MODEL INPUT_USD_PER_MTOK OUTPUT_USD_PER_MTOK  "
                                    "(use the model id as shown in the Models table)")
        telemetry.set_price(model, inp, out)
        return Text.from_markup(f"[green]priced {model}: ${inp}/M in, ${out}/M out[/green] (applies to new and recorded calls)")
    return Group(Text("unknown /settings command", style="yellow"), Text(HELP))


def live(console: Console, period: str = DEFAULT_PERIOD) -> None:
    """Refreshing overview until q / Esc / Ctrl+C."""
    from rich.live import Live
    try:
        import msvcrt
    except ImportError:
        msvcrt = None
    with Live(overview(telemetry.load(), period), console=console, refresh_per_second=2, screen=True) as view:
        try:
            while True:
                for _ in range(20):
                    if msvcrt and msvcrt.kbhit() and msvcrt.getwch() in ("q", "Q", "\x1b"):
                        return
                    time.sleep(0.1)
                view.update(overview(telemetry.load(), period))
        except KeyboardInterrupt:
            return
