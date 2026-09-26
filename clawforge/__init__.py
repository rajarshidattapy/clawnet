"""ClawForge — ClawNet as an agentic harness, orchestrated by TrueForge.

    Agent -> TrueForge (sessions, subagents, approvals) -> ClawForge MCP server
          -> ClawNet capabilities (policy, sandbox, monitor, memory) -> machine

The core/ modules use flat imports (`import policy`), so core/ goes on sys.path.
"""
import os
import sys

CORE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core")
if CORE_DIR not in sys.path:
    sys.path.insert(0, CORE_DIR)

import logging

# The MCP / TrueForge SDKs log every HTTP request at INFO; keep the console clean.
for _name in ("httpx", "httpcore", "mcp", "uvicorn"):
    logging.getLogger(_name).setLevel(logging.WARNING)

if sys.platform == "win32":        # same UTF-8 console setup as the ClawNet monitor
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
