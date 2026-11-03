"""Standalone ClawForge terminal.

    (none) | console    open the local security copilot
    status              show local machine and sandbox status
    settings ...        view or change local model and telemetry settings
    serve               expose read-only and sandbox tools over localhost MCP
    tools               list MCP tools and their safety tier
    action ...          run a host-changing action after local confirmation

TrueForge is not required. ClawForge's local terminal owns model routing,
approvals, settings, and the optional MCP integration surface.
"""
from __future__ import annotations

import sys

import clawforge  # noqa: F401


def main(argv: list[str] | None = None) -> int:
    from clawforge.native import load_env

    load_env()
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("console", "ui", "copilot", "chat"):
        from clawforge.native import console
        console()
        return 0
    if argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "serve":
        from clawforge.mcp_server import serve
        serve()
    elif cmd == "status":
        from clawforge.native import status
        status()
    elif cmd == "settings":
        from clawforge.native import settings
        settings(rest)
    elif cmd == "tools":
        from clawforge.native import tools
        tools()
    elif cmd == "action":
        from clawforge.native import action
        return action(rest)
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
