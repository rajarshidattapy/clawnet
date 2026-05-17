#!/usr/bin/env bash
#
# run-all.sh - Start the K8sWhisperer backend and frontend in parallel.
#
# Usage: ./scripts/run-all.sh
#
# Sends SIGTERM to both processes on Ctrl-C for clean shutdown.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

BACKEND_PID=""
FRONTEND_PID=""

cleanup() {
  echo ""
  info "Shutting down..."
  [ -n "$BACKEND_PID" ]  && kill "$BACKEND_PID"  2>/dev/null && info "Backend stopped."
  [ -n "$FRONTEND_PID" ] && kill "$FRONTEND_PID" 2>/dev/null && info "Frontend stopped."
  wait 2>/dev/null
  exit 0
}

trap cleanup SIGINT SIGTERM

# --- Backend ------------------------------------------------------------------

BACKEND_HOST="${BACKEND_HOST:-0.0.0.0}"
BACKEND_PORT="${BACKEND_PORT:-8000}"

info "Starting backend (uvicorn) on ${BACKEND_HOST}:${BACKEND_PORT}..."
(
  cd "$PROJECT_ROOT"
  python -m uvicorn src.api.server:app \
    --host "$BACKEND_HOST" \
    --port "$BACKEND_PORT" \
    --reload \
    --reload-dir src \
    2>&1 | while IFS= read -r line; do echo -e "${CYAN}[backend]${NC}  $line"; done
) &
BACKEND_PID=$!

# --- Frontend -----------------------------------------------------------------

FRONTEND_DIR="${PROJECT_ROOT}/frontend"
FRONTEND_PORT="${FRONTEND_PORT:-3000}"

if [ -f "${FRONTEND_DIR}/package.json" ]; then
  info "Starting frontend (npm run dev) on port ${FRONTEND_PORT}..."
  (
    cd "$FRONTEND_DIR"
    PORT="$FRONTEND_PORT" npm run dev \
      2>&1 | while IFS= read -r line; do echo -e "${YELLOW}[frontend]${NC} $line"; done
  ) &
  FRONTEND_PID=$!
else
  warn "No package.json found in frontend/. Skipping frontend startup."
  warn "To start the frontend, add a package.json to ${FRONTEND_DIR}."
fi

# --- Wait for processes -------------------------------------------------------

echo ""
info "K8sWhisperer is running. Press Ctrl-C to stop."
info "  Backend:  http://localhost:${BACKEND_PORT}"
[ -n "$FRONTEND_PID" ] && info "  Frontend: http://localhost:${FRONTEND_PORT}"
echo ""

wait
