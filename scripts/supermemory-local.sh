#!/usr/bin/env bash
# Start the self-hosted Supermemory server for ClawNet's evidence memory.
#
#   bash scripts/supermemory-local.sh
#
# Runs `bunx supermemory local` inside WSL Ubuntu (the binary is Linux-only —
# it does not run natively on Windows). WSL2 forwards localhost, so the server
# is reachable from Windows at http://localhost:6767.
#
# On first boot it prints an API key and saves it to ~/.supermemory/api-key
# (inside WSL). Put that key + the URL in .env so ClawNet mirrors evidence to it:
#     SUPERMEMORY_API_KEY=sm_...
#     SUPERMEMORY_API_URL=http://localhost:6767
#
# Without the server, ClawNet still works — the JSONL evidence store
# (~/.clawnet/evidence.jsonl) is the source of truth; the server only adds
# semantic search. See docs/supermemory.md.
#
# Prereq (one-time, native bun in WSL — Windows bun on /mnt/c will not work):
#   wsl -d Ubuntu -- bash -lc 'curl -fsSL -o /tmp/bun.zip \
#     https://github.com/oven-sh/bun/releases/latest/download/bun-linux-x64.zip \
#     && python3 -c "import zipfile;zipfile.ZipFile(\"/tmp/bun.zip\").extractall(\"/tmp/b\")" \
#     && mkdir -p ~/.bun/bin && cp /tmp/b/*/bun ~/.bun/bin/bun && chmod +x ~/.bun/bin/bun'

set -e
# Forward the host OpenAI key into WSL (server needs one LLM key at first boot).
WSLENV=OPENAI_API_KEY/u wsl.exe -d Ubuntu -- bash -lc \
  'export SUPERMEMORY_DATA_DIR=$HOME/.supermemory; exec "$HOME/.bun/bin/bun" x supermemory local'
