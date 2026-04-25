#!/usr/bin/env python3
"""ClawNet v2/v3 launcher — run from the repo root or via `clawnet` CLI."""
import sys
import os
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "core"))

import clawnet as _cw


def main() -> None:
    args = sys.argv[1:]
    if "--copilot" in args:
        _cw.run_copilot()
    else:
        threading.Thread(target=_cw._fetch_public_ip, daemon=True).start()
        _cw.run_monitor(
            resolve="--resolve" in args,
            auto="--auto"    in args,
        )


if __name__ == "__main__":
    main()
