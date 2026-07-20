#!/bin/bash
# End-to-end test for parcagpu Kubernetes deployment.
# Deploys the webhook, creates a mock workload, and verifies metrics.
#
# Prerequisites:
#   - A running Kubernetes cluster (kind, minikube, or real cluster)
#   - kubectl configured
#   - Docker (for building images)
#
# Usage:
#   ./deploy/k8s/test-e2e.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=== Parcagpu E2E Test ==="
echo

# Step 1: Apply webhook manifests
echo "--- Applying webhook RBAC ---"
kubectl apply -f "$ROOT/deploy/k8s/webhook-rbac.yaml"

echo "--- Applying webhook deployment ---"
kubectl apply -f "$ROOT/deploy/k8s/webhook-deployment.yaml"

echo "--- Applying webhook config ---"
kubectl apply -f "$ROOT/deploy/k8s/webhook-config.yaml"

echo "--- Running TLS cert generation job ---"
kubectl apply -f "$ROOT/deploy/k8s/webhook-tls-job.yaml"
kubectl wait --for=condition=complete job/parcagpu-webhook-tls -n kube-system --timeout=60s || true

# Step 2: Wait for webhook to be ready
echo "--- Waiting for webhook deployment ---"
kubectl rollout status deployment/parcagpu-webhook -n kube-system --timeout=60s

# Step 3: Apply Prometheus config
echo "--- Applying Prometheus config ---"
kubectl apply -f "$ROOT/deploy/k8s/prometheus-config.yaml"

# Step 4: Apply Grafana
echo "--- Applying Grafana ---"
kubectl apply -f "$ROOT/deploy/k8s/grafana-deployment.yaml"

# Step 5: Create mock demo workload
echo "--- Creating mock demo workload ---"
kubectl apply -f "$ROOT/deploy/k8s/demo-workload-mock.yaml"

# Step 6: Wait for pod to be ready
echo "--- Waiting for demo pod ---"
kubectl wait --for=condition=Ready pod/parcagpu-demo-mock --timeout=120s || {
  echo "Pod not ready, showing status:"
  kubectl get pod parcagpu-demo-mock -o yaml
  exit 1
}

# Step 7: Verify injection happened
echo "--- Verifying injection ---"
if kubectl get pod parcagpu-demo-mock -o jsonpath='{.spec.shareProcessNamespace}' | grep -q true; then
  echo "PASS: shareProcessNamespace is true"
else
  echo "FAIL: shareProcessNamespace is not true"
  kubectl get pod parcagpu-demo-mock -o yaml
  exit 1
fi

if kubectl get pod parcagpu-demo-mock -o jsonpath='{.spec.containers[*].name}' | grep -q parcagpu-observer; then
  echo "PASS: observer sidecar is present"
else
  echo "FAIL: observer sidecar is missing"
  exit 1
fi

if kubectl get pod parcagpu-demo-mock -o jsonpath='{.spec.initContainers[*].name}' | grep -q parcagpu-init; then
  echo "PASS: init container is present"
else
  echo "FAIL: init container is missing"
  exit 1
fi

# Step 8: Wait for metrics to be available
echo "--- Waiting for metrics (15s) ---"
sleep 15

# Step 9: Port-forward and check metrics
echo "--- Checking metrics ---"
kubectl port-forward pod/parcagpu-demo-mock 9090:9090 &
FORWARD_PID=$!
sleep 3

METRICS=$(curl -s http://localhost:9090/metrics || true)
kill $FORWARD_PID 2>/dev/null || true

if echo "$METRICS" | grep -q "parcagpu_probe_attached"; then
  echo "PASS: parcagpu metrics are available"
  echo "$METRICS" | grep "^parcagpu_" | head -20
else
  echo "FAIL: no parcagpu metrics found"
  echo "Metrics output:"
  echo "$METRICS" | head -20
  kubectl logs parcagpu-demo-mock -c parcagpu-observer --tail=20
  exit 1
fi

echo
echo "=== E2E TEST PASSED ==="
echo
echo "To view the Grafana dashboard:"
echo "  kubectl port-forward svc/parcagpu-grafana 3000:3000"
echo "  Open http://localhost:3000"
