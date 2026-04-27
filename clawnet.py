#!/usr/bin/env python3
"""ClawNet v2/v3 launcher — run from the repo root or via `clawnet` CLI."""
import sys
import os
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "core"))

import clawnet as _cw
from sandbox import SandboxRunner


def main() -> None:
    args = sys.argv[1:]
    if not args:
        threading.Thread(target=_cw._fetch_public_ip, daemon=True).start()
        _cw.run_monitor(resolve=False, auto=False)
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
    else:
        threading.Thread(target=_cw._fetch_public_ip, daemon=True).start()
        _cw.run_monitor(
            resolve="--resolve" in args,
            auto="--auto"    in args,
        )


if __name__ == "__main__":
    main()
