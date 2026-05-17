#!/usr/bin/env bash
# Setup script for running K8sWhisperer with Docker
# Prerequisites: docker, docker-compose, kind, kubectl
set -euo pipefail

echo "=== K8sWhisperer Docker Setup ==="
echo ""

# 1. Check prerequisites
for cmd in docker kind kubectl; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd is not installed"
        exit 1
    fi
done
echo "[OK] Prerequisites: docker, kind, kubectl"

# 2. Check/create kind cluster
if kind get clusters 2>/dev/null | grep -q "atlanclaw"; then
    echo "[OK] Kind cluster 'atlanclaw' exists"
else
    echo "[..] Creating kind cluster 'atlanclaw'..."
    kind create cluster --name atlanclaw
    echo "[OK] Cluster created"
fi

# 3. Setup namespace and RBAC
kubectl apply -f k8s/namespace.yaml 2>/dev/null || true
kubectl apply -f k8s/rbac.yaml 2>/dev/null || true
echo "[OK] Namespace and RBAC configured"

# 4. Create Docker-compatible kubeconfig
# Kind clusters listen on 127.0.0.1 which isn't reachable from inside Docker.
# We rewrite the server URL to host.docker.internal.
DOCKER_KUBECONFIG="$(pwd)/.docker-kubeconfig"
kubectl config view --raw > "$DOCKER_KUBECONFIG"

# Get the current server URL and replace 127.0.0.1 / localhost with host.docker.internal
if [[ "$(uname)" == "Darwin" ]] || [[ "$(uname)" == *"MINGW"* ]]; then
    # macOS / Windows — host.docker.internal works natively
    sed -i.bak 's|https://127\.0\.0\.1:|https://host.docker.internal:|g' "$DOCKER_KUBECONFIG"
    sed -i.bak 's|https://localhost:|https://host.docker.internal:|g' "$DOCKER_KUBECONFIG"
    rm -f "${DOCKER_KUBECONFIG}.bak"
else
    # Linux — host.docker.internal may need extra_hosts (docker-compose handles this)
    sed -i 's|https://127\.0\.0\.1:|https://host.docker.internal:|g' "$DOCKER_KUBECONFIG"
    sed -i 's|https://localhost:|https://host.docker.internal:|g' "$DOCKER_KUBECONFIG"
fi
echo "[OK] Docker-compatible kubeconfig at $DOCKER_KUBECONFIG"

# 5. Check .env file
if [ ! -f .env ]; then
    echo ""
    echo "WARNING: No .env file found!"
    echo "Copy .env.example to .env and fill in your credentials:"
    echo "  cp .env.example .env"
    echo "  # Then edit .env with your LLM_API_KEY, SLACK tokens, etc."
    echo ""
    exit 1
fi
echo "[OK] .env file found"

# 6. Build and start
echo ""
echo "=== Building Docker images ==="
KUBECONFIG="$DOCKER_KUBECONFIG" docker compose build

echo ""
echo "=== Starting K8sWhisperer ==="
KUBECONFIG="$DOCKER_KUBECONFIG" docker compose up -d

echo ""
echo "=== K8sWhisperer is running! ==="
echo "  Frontend:  http://localhost:3000"
echo "  Backend:   http://localhost:8000"
echo ""
echo "Deploy demo scenarios:"
echo "  kubectl apply -f k8s/demo-scenarios/crashloop-demo.yaml"
echo "  kubectl apply -f k8s/demo-scenarios/oomkill-deploy-demo.yaml"
echo ""
echo "Stop: docker compose down"
echo "Logs: docker compose logs -f"
