"""python -m clawforge <command>

    serve            start the ClawForge MCP server (ClawNet capabilities as tools)
    setup            register the OpenAI provider, MCP connector and agent in TrueForge
    run "<task>"     run one task end to end, pausing at every approval
    chat             multi-turn session in the terminal
    tools            list the tools and their approval tier
"""
import sys

import clawforge  # noqa: F401


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "serve":
        from clawforge.harness import load_env
        load_env()
        from clawforge.mcp_server import serve
        serve()
    elif cmd == "setup":
        from clawforge.harness import setup
        setup()
    elif cmd == "run":
        if not rest:
            print('Usage: python -m clawforge run "<task>"')
            return 2
        from clawforge.harness import run
        run(" ".join(rest))
    elif cmd == "chat":
        from clawforge.harness import chat
        chat()
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


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
