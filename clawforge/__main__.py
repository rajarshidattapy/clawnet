"""python -m clawforge [command]

    (none)           open the ClawForge console: status checks + chat with the agent
    serve            start the ClawForge MCP server (ClawNet capabilities as tools)
    setup            register the OpenAI provider, MCP connector and agent in TrueForge
    trueforge        install (once) and start the TrueForge server, configured for ClawForge
    run "<task>"     run one task end to end, pausing at every approval
    chat             multi-turn session in the terminal
    tools            list the tools and their approval tier
"""
import sys

import clawforge  # noqa: F401


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("console", "ui"):
        from clawforge.tui import main as console_main
        console_main()
        return 0
    if argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "serve":
        from clawforge.harness import load_env
        load_env()
        from clawforge.mcp_server import serve
        serve()
    elif cmd == "setup":
        from clawforge.tui import _setup
        return 0 if _setup() else 1
    elif cmd == "run":
        if not rest:
            print('Usage: python -m clawforge run "<task>"')
            return 2
        from clawforge.harness import console
        from clawforge.tui import preflight, ready, status_panel
        checks = preflight()
        if not ready(checks):
            console.print(status_panel(checks))
            return 1
        from clawforge.harness import run
        run(" ".join(rest))
    elif cmd == "trueforge":
        return _trueforge()
    elif cmd == "chat":
        from clawforge.tui import main as console_main
        console_main()
    elif cmd == "tools":
        import asyncio
        from clawforge.harness import tier
        from clawforge.mcp_server import mcp
        for t in asyncio.run(mcp.list_tools()):
            a = t.annotations
            print(f"{tier(t.name):<8} {t.name:<22} readOnly={a.readOnlyHint!s:<5} destructive={a.destructiveHint}")
    else:
        print(__doc__)
        return 2
    return 0


def _trueforge() -> int:
    """Install TrueForge into .trueforge/ (once) and run it for ClawForge.

    Not `npx`: npm 11's npx install lock times out on Windows for a package this
    size ("npm error code ECOMPROMISED / Lock compromised"). A plain local
    `npm install` has no such lock.
    """
    import os
    import shutil
    import subprocess
    from pathlib import Path
    from clawforge.harness import load_env
    from clawforge.mcp_server import host

    load_env()
    npm = shutil.which("npm")
    node = shutil.which("node")
    if not (npm and node):
        print("Node.js 22.14+ is required (node and npm on PATH).")
        return 1
    runtime = Path(clawforge.CORE_DIR).parent / ".trueforge"
    cli = runtime / "node_modules" / "@truefoundry" / "trueforge" / "dist" / "cli.js"
    if not cli.exists() or "--update" in sys.argv:
        runtime.mkdir(exist_ok=True)
        if not (runtime / "package.json").exists():
            (runtime / "package.json").write_text('{"name":"clawforge-trueforge-runtime","private":true}')
        print(f"Installing @truefoundry/trueforge into {runtime} …")
        rc = subprocess.call([npm, "install", "--no-fund", "--no-audit", "@truefoundry/trueforge@latest"],
                             cwd=runtime)
        if rc != 0:
            return rc
    env = dict(os.environ)
    # TrueForge blocks private/loopback MCP URLs by default; allow exactly the
    # ClawForge MCP host, nothing broader.
    env.setdefault("OUTBOUND_URL_ALLOWED_HOSTS", f'["{host()}", "localhost"]')
    # Room for a full sandbox run (CLAWFORGE_SANDBOX_TIMEOUT) inside one tool call.
    env.setdefault("MCP_REQUEST_TIMEOUT_MS", "300000")
    try:
        return subprocess.call([node, str(cli)], cwd=runtime, env=env)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
