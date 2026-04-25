#!/usr/bin/env python3
"""ClawNet launcher — run from the repo root."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "core"))

from clawnet import run_monitor, run_copilot
import threading
from clawnet import _fetch_public_ip

if __name__ == "__main__":
    args = sys.argv[1:]
    if "--copilot" in args:
        run_copilot()
    else:
        threading.Thread(target=_fetch_public_ip, daemon=True).start()
        run_monitor(
            resolve="--resolve" in args,
            auto="--auto"    in args,
        )
