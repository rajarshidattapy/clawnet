#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONTRACT_DIR="$PROJECT_DIR/contracts/incident-audit"

echo "=== K8sWhisperer Stellar Contract Deployment ==="
echo ""

# Check prerequisites
if ! command -v stellar &> /dev/null; then
    echo "ERROR: stellar-cli not found. Install with:"
    echo "  brew install stellar-cli"
    echo "  OR cargo install --locked stellar-cli"
    exit 1
fi

# Generate identity if not exists
if ! stellar keys show alice 2>/dev/null; then
    echo "Generating new testnet identity 'alice'..."
    stellar keys generate alice --network testnet --fund
    echo "Identity created and funded."
else
    echo "Using existing identity 'alice'."
fi

echo ""
echo "Building contract..."
cd "$CONTRACT_DIR"
stellar contract build

echo ""
echo "Deploying to Stellar testnet..."
CONTRACT_ID=$(stellar contract deploy \
    --wasm target/wasm32-unknown-unknown/release/incident_audit.wasm \
    --source-account alice \
    --network testnet)

echo ""
echo "Contract deployed!"
echo "Contract ID: $CONTRACT_ID"
echo ""

# Test the contract
echo "Testing store_incident..."
stellar contract invoke \
    --id "$CONTRACT_ID" \
    --source-account alice \
    --network testnet \
    -- store_incident \
    --incident_id "test-001" \
    --anomaly_type "CrashLoopBackOff" \
    --action_taken "delete_pod" \
    --timestamp 1711700000 \
    --confidence_score 9000 \
    --was_auto_executed true \
    --diagnosis_summary "Test deployment verification"

echo ""
echo "Testing get_count..."
COUNT=$(stellar contract invoke \
    --id "$CONTRACT_ID" \
    --source-account alice \
    --network testnet \
    -- get_count)
echo "Record count: $COUNT"

echo ""
echo "=== Deployment complete ==="
echo ""
echo "Add this to your .env file:"
echo "  STELLAR_CONTRACT_ID=$CONTRACT_ID"
echo ""
echo "Explorer: https://stellar.expert/explorer/testnet/contract/$CONTRACT_ID"
