#!/usr/bin/env bash
#
# deploy-scenarios.sh - Deploy all K8sWhisperer demo scenarios to the cluster.
#
# Usage: ./scripts/deploy-scenarios.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCENARIOS_DIR="${PROJECT_ROOT}/k8s/demo-scenarios"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# --- Pre-flight checks -------------------------------------------------------

if ! kubectl get namespace k8swhisperer-demo &>/dev/null; then
  error "Namespace 'k8swhisperer-demo' does not exist."
  error "Run ./scripts/setup-minikube.sh first."
  exit 1
fi

# --- Deploy scenarios ---------------------------------------------------------

SCENARIO_FILES=("${SCENARIOS_DIR}"/*.yaml)

if [ ${#SCENARIO_FILES[@]} -eq 0 ]; then
  warn "No scenario files found in ${SCENARIOS_DIR}"
  exit 0
fi

info "Deploying ${#SCENARIO_FILES[@]} demo scenario(s)..."

for file in "${SCENARIO_FILES[@]}"; do
  name="$(basename "$file")"
  info "Applying ${name}..."
  kubectl apply -f "$file"
done

echo ""
info "All scenarios deployed. Waiting a few seconds for pods to start..."
sleep 5

echo ""
echo "--- Pod Status ---"
kubectl get pods -n k8swhisperer-demo -o wide

echo ""
echo "--- Deployment Status ---"
kubectl get deployments -n k8swhisperer-demo -o wide

echo ""
info "Demo scenarios are active. Use 'kubectl get pods -n k8swhisperer-demo -w' to watch."
