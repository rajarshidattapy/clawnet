#!/usr/bin/env bash
#
# setup-minikube.sh - Bootstrap a minikube cluster for K8sWhisperer development.
#
# Usage: ./scripts/setup-minikube.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# --- Pre-flight checks -------------------------------------------------------

for cmd in minikube kubectl; do
  if ! command -v "$cmd" &>/dev/null; then
    error "$cmd is not installed. Please install it first."
    exit 1
  fi
done

# --- Start minikube -----------------------------------------------------------

PROFILE="k8swhisperer"

if minikube status -p "$PROFILE" &>/dev/null; then
  info "Minikube profile '${PROFILE}' is already running."
else
  info "Starting minikube (profile=${PROFILE}, cpus=4, memory=8192MB)..."
  minikube start \
    --profile "$PROFILE" \
    --cpus 4 \
    --memory 8192 \
    --driver docker \
    --kubernetes-version stable
fi

# Point kubectl at the right profile
minikube update-context -p "$PROFILE"

# --- Enable addons ------------------------------------------------------------

info "Enabling metrics-server addon..."
minikube addons enable metrics-server -p "$PROFILE"

# --- Apply namespace and RBAC -------------------------------------------------

info "Applying namespace..."
kubectl apply -f "${PROJECT_ROOT}/k8s/namespace.yaml"

info "Applying RBAC configuration..."
kubectl apply -f "${PROJECT_ROOT}/k8s/rbac.yaml"

# --- Verification -------------------------------------------------------------

info "Verifying setup..."

echo ""
echo "--- Namespace ---"
kubectl get namespace k8swhisperer-demo

echo ""
echo "--- ServiceAccount ---"
kubectl get serviceaccount k8swhisperer-agent -n k8swhisperer-demo

echo ""
echo "--- Role ---"
kubectl get role k8swhisperer-agent-role -n k8swhisperer-demo

echo ""
echo "--- RoleBinding ---"
kubectl get rolebinding k8swhisperer-agent-rolebinding -n k8swhisperer-demo

echo ""
echo "--- ClusterRole ---"
kubectl get clusterrole k8swhisperer-agent-clusterrole

echo ""
echo "--- ClusterRoleBinding ---"
kubectl get clusterrolebinding k8swhisperer-agent-clusterrolebinding

echo ""
echo "--- Metrics Server ---"
minikube addons list -p "$PROFILE" | grep metrics-server

echo ""
info "Setup complete. Minikube profile '${PROFILE}' is ready."
info "Run 'minikube profile ${PROFILE}' to set it as default."
