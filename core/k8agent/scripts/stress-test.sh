#!/usr/bin/env bash
# Deploy webapp + HPA + load generator
# Watch the agent handle CPUThrottling and HPA scaling
echo "Deploying stress test..."
kubectl apply -f k8s/demo-scenarios/hpa-stress-demo.yaml -n k8swhisperer-demo
echo "Waiting 30s for deployment..."
sleep 30
echo "Starting load generator..."
kubectl apply -f k8s/demo-scenarios/stress-generator.yaml -n k8swhisperer-demo
echo "Load generator running. Watch the agent handle scaling."
echo "Monitor: kubectl get hpa -n k8swhisperer-demo -w"
