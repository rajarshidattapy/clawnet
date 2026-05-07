#!/usr/bin/env python3
"""ClawNet v2/v3 launcher — run from the repo root or via `clawnet` CLI."""
import sys
import os
import threading
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "core"))

import clawnet as _cw
from sandbox import SandboxRunner


def main() -> None:
    args = sys.argv[1:]
    if not args:
        threading.Thread(target=_cw._fetch_public_ip, daemon=True).start()
        _cw.run_monitor(resolve=False, auto=False)
        return

    if "--isolation" in args:
        from isolation import run_isolation_mode
        run_isolation_mode()
        return

    if "--copilot" in args:
        _cw.run_copilot()
    elif args[0] == "run":
        if len(args) < 2:
            print("Usage: clawnet run <path> [--cmd \"custom command\"] [--deep] [--offline]")
            sys.exit(2)
        runner = SandboxRunner()
        target = args[1]
        runtime_cmd = ""
        deep_scan = "--deep" in args
        force_network_mode = "none" if "--offline" in args else ""
        if "--cmd" in args:
            i = args.index("--cmd")
            if i + 1 < len(args):
                runtime_cmd = args[i + 1]
        result = runner.run_target(
            target,
            runtime_command=runtime_cmd,
            deep_scan=deep_scan,
            force_network_mode=force_network_mode,
        )
        approved = runner.promotion_gate(result)
        if approved:
            print("Promotion approved.")
        else:
            print("Promotion denied.")
            sys.exit(1)
    elif args[0] == "clone":
        if len(args) < 2:
            print("Usage: clawnet clone <git-url> [--cmd \"custom command\"] [--deep] [--offline]")
            sys.exit(2)
        runner = SandboxRunner()
        git_url = args[1]
        runtime_cmd = ""
        deep_scan = "--deep" in args
        force_network_mode = "none" if "--offline" in args else ""
        if "--cmd" in args:
            i = args.index("--cmd")
            if i + 1 < len(args):
                runtime_cmd = args[i + 1]
        result = runner.clone_and_run(
            git_url,
            runtime_command=runtime_cmd,
            deep_scan=deep_scan,
            force_network_mode=force_network_mode,
        )
        approved = runner.promotion_gate(result)
        if approved:
            print("Promotion approved.")
        else:
            print("Promotion denied.")
            sys.exit(1)
    elif args[0] == "policy-init":
        runner = SandboxRunner()
        path = runner.ensure_policy_file()
        print(f"Sandbox policy available at: {path}")
    elif args[0] == "install-interceptors":
        runner = SandboxRunner()
        files = runner.install_interceptors()
        print("Installed interceptor helpers:")
        for p in files:
            print(f"- {p}")
    elif args[0] == "sandbox-list":
        import json as _json
        import time as _time
        from rich.console import Console as _Console
        from rich.table import Table as _Table
        runner = SandboxRunner()
        runs = runner.list_runs(limit=int(args[1]) if len(args) > 1 else 20)
        if not runs:
            print("No sandbox runs recorded yet.")
        else:
            c = _Console()
            t = _Table(title="Recent Sandbox Runs", border_style="cyan")
            t.add_column("Run ID", style="cyan", no_wrap=True)
            t.add_column("Target")
            t.add_column("Risk", justify="center")
            t.add_column("Score", justify="right")
            t.add_column("Recommendation")
            t.add_column("When")
            for run in runs:
                ts = run.get("ts", 0)
                when = _time.strftime("%Y-%m-%d %H:%M", _time.localtime(ts)) if ts else "?"
                level = run.get("risk_level", "?")
                color = {"SAFE": "green", "SUSPICIOUS": "yellow", "DANGEROUS": "red"}.get(level, "white")
                t.add_row(
                    run.get("run_id", "?"),
                    Path(run.get("target", "?")).name,
                    f"[{color}]{level}[/{color}]",
                    str(run.get("risk_score", 0)),
                    run.get("recommendation", "?"),
                    when,
                )
            c.print(t)
    elif args[0] == "sandbox-report":
        import json as _json
        if len(args) < 2:
            print("Usage: clawnet sandbox-report <run-id>")
            sys.exit(2)
        runner = SandboxRunner()
        report = runner.load_report(args[1])
        if not report:
            print(f"No report found for run ID: {args[1]}")
            sys.exit(1)
        print(_json.dumps(report, indent=2))
    else:
        threading.Thread(target=_cw._fetch_public_ip, daemon=True).start()
        _cw.run_monitor(
            resolve="--resolve" in args,
            auto="--auto"    in args,
        )


if __name__ == "__main__":
    main()
