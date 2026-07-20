# Parcagpu: End-to-End Build & Install Guide

This guide walks through building all three container images, pushing them to
a registry, deploying to Kubernetes, and verifying the full pipeline works.

## Prerequisites

### Build machine (Linux, x86_64 or arm64)

- **Docker** with buildx (`docker buildx version` ≥ 0.10)
- **Go** 1.25+ (only needed for local webhook tests)
- **clang, libbpf-dev, bpftool** (only needed to generate `vmlinux.h` and run
  local BPF tests)
- **CMake, g++, systemtap-sdt-dev** (only needed for local `.so` builds)

### Target Kubernetes cluster

- Kubernetes 1.25+
- `kubectl` configured and connected
- For the mock demo: any node type (no GPU needed)
- For the real GPU demo: nodes with NVIDIA GPUs + the NVIDIA device plugin

### Registry

A container registry you can push to. This guide uses `ghcr.io/parca-dev` —
replace with your own registry throughout.

---

## Part 1: Build the images

There are three images:

| Image | Purpose | Dockerfile |
|-------|---------|------------|
| `parcagpu` | The `.so` library (injected into CUDA workloads via init container) | `Dockerfile` |
| `parcagpu-observer` | The eBPF observer sidecar (attaches uprobes, exports metrics) | `Dockerfile.observer` |
| `parcagpu-webhook` | The admission webhook server (auto-injects the above two) | `deploy/webhook/Dockerfile` |
| `parcagpu-test` | Mock CUPTI test binary + cubin (for GPU-less demo) | `Dockerfile.test` |

### 1.1 Log in to your registry

```bash
# For ghcr.io, create a Personal Access Token with write:packages scope
echo "$GITHUB_TOKEN" | docker login ghcr.io -u YOUR_GH_USERNAME --password-stdin
```

### 1.2 Build and push the `.so` library image

This is the existing parcagpu library image. If you haven't changed the C/C++
source (`src/`), you can skip this and use `ghcr.io/parca-dev/parcagpu:latest`
directly.

```bash
cd /path/to/parcagpu

# Build locally to verify it compiles (optional, requires CMake + CUDA headers)
make local

# Build and push multi-arch image
make docker-push IMAGE=ghcr.io/YOUR_ORG/parcagpu IMAGE_TAG=latest
```

This produces `ghcr.io/YOUR_ORG/parcagpu:latest` containing
`/usr/lib/libparcagpucupti.so`, built for both `linux/amd64` and `linux/arm64`.

### 1.3 Build and push the observer image

The observer image contains:
- The Go binary with BPF objects embedded (via bpf2go)
- `llvm-dwarfdump` for PC sample symbolization
- A copy of `libparcagpucupti.so` (for reading USDT probe locations at startup)

**Before building**, you must generate `vmlinux.h` — the BPF vmlinux header
that describes the host kernel's types. This must be generated on a Linux
machine (the Docker build cannot do it because `/sys/kernel/btf` is not
available inside the build container).

```bash
# Generate vmlinux.h (one-time, on any Linux host with bpftool)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > test/bpf/vmlinux.h
```

```bash
# Build and push multi-arch observer image
make docker-push-observer \
  OBSERVER_IMAGE=ghcr.io/YOUR_ORG/parcagpu-observer \
  OBSERVER_IMAGE_TAG=latest
```

This produces `ghcr.io/YOUR_ORG/parcagpu-observer:latest` for both architectures.

**Note:** The `vmlinux.h` file is kernel-version-specific at the BTF level, but
bpf2go compiles with CO-RE (Compile Once, Run Everywhere), so a `vmlinux.h`
generated on one kernel will work on most other kernels. For maximum
compatibility, generate it on a recent kernel (5.15+).

### 1.4 Build and push the webhook image

The webhook is a standalone Go binary with no external runtime dependencies.

```bash
# Build the webhook image
docker build -f deploy/webhook/Dockerfile \
  -t ghcr.io/YOUR_ORG/parcagpu-webhook:latest \
  deploy/webhook/

# Push it
docker push ghcr.io/YOUR_ORG/parcagpu-webhook:latest
```

### 1.5 Build and push the test image (mock demo only)

The test image contains the mock CUPTI/CUDA libraries and `test_cupti_prof`
binary for the GPU-less demo. Only needed if you want to run the mock demo.

```bash
# Build the test image (requires the .so from build-amd64)
make docker-push-test \
  TEST_IMAGE=ghcr.io/YOUR_ORG/parcagpu-test \
  TEST_IMAGE_TAG=latest
```

### 1.6 Verify all images are pushed

```bash
# List all four images in your registry
docker buildx imagetools inspect ghcr.io/YOUR_ORG/parcagpu:latest
docker buildx imagetools inspect ghcr.io/YOUR_ORG/parcagpu-observer:latest
docker buildx imagetools inspect ghcr.io/YOUR_ORG/parcagpu-webhook:latest
docker buildx imagetools inspect ghcr.io/YOUR_ORG/parcagpu-test:latest
```

Each should show both `linux/amd64` and `linux/arm64` platforms (except the
webhook, which is single-arch via standard `docker build`).

---

## Part 2: Update manifests with your image references

Before deploying, update the image references in the K8s manifests to point to
your registry.

```bash
cd /path/to/parcagpu

# Replace all ghcr.io/parca-dev references with your registry
# (Skip this step if you're using the published parca-dev images)
sed -i 's|ghcr.io/parca-dev/parcagpu|ghcr.io/YOUR_ORG/parcagpu|g' \
  deploy/k8s/*.yaml deploy/webhook/main.go

# Verify the changes
grep -r "ghcr.io" deploy/k8s/ deploy/webhook/main.go
```

The image references are in:
- `deploy/k8s/webhook-deployment.yaml` → `ghcr.io/YOUR_ORG/parcagpu-webhook:latest`
- `deploy/k8s/demo-workload-mock.yaml` → `ghcr.io/YOUR_ORG/parcagpu-test:latest`
- `deploy/k8s/demo-workload-gpu.yaml` → (uses the test image too)
- `deploy/webhook/main.go` → `defaultLibImage` and `defaultObsImage` constants
  (baked into the webhook binary at build time)

---

## Part 3: Deploy to Kubernetes

### 3.1 Apply the webhook infrastructure

```bash
# RBAC (ServiceAccount, ClusterRole, ClusterRoleBinding)
kubectl apply -f deploy/k8s/webhook-rbac.yaml

# Webhook Deployment + Service
kubectl apply -f deploy/k8s/webhook-deployment.yaml

# MutatingWebhookConfiguration (caBundle is empty, patched by the TLS Job)
kubectl apply -f deploy/k8s/webhook-config.yaml

# TLS cert generation Job (generates self-signed cert, creates TLS secret,
# patches the webhook config with the CA bundle)
kubectl apply -f deploy/k8s/webhook-tls-job.yaml

# Wait for the TLS Job to complete
kubectl wait --for=condition=complete \
  job/parcagpu-webhook-tls -n kube-system --timeout=60s
```

### 3.2 Verify the webhook is running

```bash
# Check the webhook pod is ready
kubectl get pods -n kube-system -l app=parcagpu-webhook

# Check the MutatingWebhookConfiguration has a CA bundle
kubectl get mutatingwebhookconfiguration parcagpu-webhook -o jsonpath='{.webhooks[0].clientConfig.caBundle}' | head -c 20
echo  # should show base64-encoded cert data
```

### 3.3 Deploy observability stack

```bash
# Prometheus scrape config + PodMonitor
kubectl apply -f deploy/k8s/prometheus-config.yaml

# Grafana with pre-built dashboard
kubectl apply -f deploy/k8s/grafana-deployment.yaml

# Wait for Grafana to be ready
kubectl rollout status deployment/parcagpu-grafana -n default --timeout=60s
```

---

## Part 4: Run a demo workload

### 4.1 Mock demo (no GPU required)

This runs the mock CUPTI test binary, which emits synthetic kernel activity
records and PC samples. It demonstrates the full pipeline on any cluster.

```bash
kubectl apply -f deploy/k8s/demo-workload-mock.yaml
```

### 4.2 Verify injection happened

```bash
# The pod should have 2 containers (workload + observer) and 1 init container
kubectl get pod parcagpu-demo-mock -o jsonpath='{.spec.containers[*].name}'
echo
# Expected: cuda-workload parcagpu-observer

kubectl get pod parcagpu-demo-mock -o jsonpath='{.spec.initContainers[*].name}'
echo
# Expected: parcagpu-init

# shareProcessNamespace should be true
kubectl get pod parcagpu-demo-mock -o jsonpath='{.spec.shareProcessNamespace}'
echo
# Expected: true

# The workload should have CUDA_INJECTION64_PATH set
kubectl get pod parcagpu-demo-mock -o jsonpath='{.spec.containers[0].env[*].name}'
echo
# Expected: ... CUDA_INJECTION64_PATH ...
```

### 4.3 Check metrics

```bash
# Port-forward to the observer sidecar's metrics port
kubectl port-forward pod/parcagpu-demo-mock 9090:9090 &

# Query the metrics
curl -s http://localhost:9090/metrics | grep parcagpu

# Expected output includes:
#   parcagpu_probe_attached{pod="parcagpu-demo-mock",namespace="default",probe_name="activity_batch"} 1
#   parcagpu_kernel_count_total{...} N
#   parcagpu_kernel_duration_seconds_bucket{...} N
#   parcagpu_bpf_stats{...,stat_name="correlations"} N
#   ...

# Clean up the port-forward
kill %1
```

### 4.4 View the Grafana dashboard

```bash
# Port-forward to Grafana
kubectl port-forward svc/parcagpu-grafana 3000:3000 &

# Open http://localhost:3000 in your browser
# (anonymous admin access is enabled by default in the deployment)

# When done:
kill %1
```

### 4.5 Real GPU demo (requires GPU nodes)

```bash
# Requires a node with an NVIDIA GPU and the NVIDIA device plugin
kubectl apply -f deploy/k8s/demo-workload-gpu.yaml

# Verify the pod is running on a GPU node
kubectl get pod parcagpu-demo-gpu -o wide

# Check metrics (same as mock demo)
kubectl port-forward pod/parcagpu-demo-gpu 9090:9090 &
curl -s http://localhost:9090/metrics | grep parcagpu
kill %1
```

---

## Part 5: Instrument your own workload

To instrument any existing CUDA workload, simply add the label
`parcagpu.dev/enabled: "true"` to the pod spec:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-cuda-app
  labels:
    parcagpu.dev/enabled: "true"  # <-- triggers injection
spec:
  containers:
    - name: app
      image: my-cuda-image:latest
      resources:
        limits:
          nvidia.com/gpu: 1
```

The webhook automatically:
1. Adds an init container that copies `libparcagpucupti.so` to a shared volume
2. Sets `CUDA_INJECTION64_PATH=/parcagpu/libparcagpucupti.so` on every container
3. Adds the observer sidecar (privileged, with metrics on port 9090)
4. Sets `shareProcessNamespace: true`
5. Adds Prometheus scrape annotations

No code changes, no rebuilds, no relinking — just a label.

---

## Part 6: Troubleshooting

### Webhook doesn't inject

```bash
# Check the webhook pod is running
kubectl get pods -n kube-system -l app=parcagpu-webhook

# Check the webhook logs
kubectl logs -n kube-system -l app=parcagpu-webhook --tail=20

# Verify the TLS Job completed and patched the caBundle
kubectl get job -n kube-system parcagpu-webhook-tls
kubectl get mutatingwebhookconfiguration parcagpu-webhook -o jsonpath='{.webhooks[0].clientConfig.caBundle}' | wc -c
# Should be > 0 (the base64-encoded cert)
```

### Observer sidecar can't find the workload PID

```bash
# Check the observer logs
kubectl logs pod/parcagpu-demo-mock -c parcagpu-observer --tail=20

# Common causes:
# 1. The workload hasn't loaded the .so yet — the observer retries for 60s
# 2. shareProcessNamespace is not true — check the pod spec
# 3. The .so path doesn't match — check -lib-path in the observer args
```

### Observer attaches but no metrics appear

```bash
# Check if the cuda_correlation probe is firing (it bumps the USDT semaphore
# that enables the activity path). If correlations=0, the library's activity
# buffer allocation is dead.
kubectl logs pod/parcagpu-demo-mock -c parcagpu-observer --tail=50 | grep correlations
# Expected: correlations=N where N > 0
```

### BPF verifier rejects the program

This means the host kernel is too old or missing BTF. Check:

```bash
# On the node (or in the pod):
kubectl exec pod/parcagpu-demo-mock -c parcagpu-observer -- uname -r
# Must be ≥ 5.15 for CO-RE BPF

kubectl exec pod/parcagpu-demo-mock -c parcagpu-observer -- ls /sys/kernel/btf/vmlinux
# Must exist — the node kernel must have BTF support
```

### Pod stays pending

```bash
kubectl describe pod parcagpu-demo-mock
# Common causes:
# - Image not found in registry (check image name and push)
# - Node doesn't have enough resources
# - For GPU demo: no nodes with nvidia.com/gpu available
```

---

## Part 7: Clean up

```bash
# Delete demo workloads
kubectl delete -f deploy/k8s/demo-workload-mock.yaml
kubectl delete -f deploy/k8s/demo-workload-gpu.yaml

# Delete observability stack
kubectl delete -f deploy/k8s/grafana-deployment.yaml
kubectl delete -f deploy/k8s/prometheus-config.yaml

# Delete webhook infrastructure
kubectl delete -f deploy/k8s/webhook-tls-job.yaml
kubectl delete -f deploy/k8s/webhook-config.yaml
kubectl delete -f deploy/k8s/webhook-deployment.yaml
kubectl delete -f deploy/k8s/webhook-rbac.yaml

# Delete the TLS secret
kubectl delete secret parcagpu-webhook-tls -n kube-system
```

---

## Quick reference: all build commands

```bash
# 1. Generate vmlinux.h (one-time, on a Linux host)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > test/bpf/vmlinux.h

# 2. Build and push all images
make docker-push IMAGE=ghcr.io/YOUR_ORG/parcagpu IMAGE_TAG=latest
make docker-push-observer OBSERVER_IMAGE=ghcr.io/YOUR_ORG/parcagpu-observer OBSERVER_IMAGE_TAG=latest
docker build -f deploy/webhook/Dockerfile -t ghcr.io/YOUR_ORG/parcagpu-webhook:latest deploy/webhook/
docker push ghcr.io/YOUR_ORG/parcagpu-webhook:latest
make docker-push-test TEST_IMAGE=ghcr.io/YOUR_ORG/parcagpu-test TEST_IMAGE_TAG=latest

# 3. Deploy to K8s
kubectl apply -f deploy/k8s/
kubectl wait --for=condition=complete job/parcagpu-webhook-tls -n kube-system --timeout=60s

# 4. Run the mock demo
kubectl apply -f deploy/k8s/demo-workload-mock.yaml

# 5. Check metrics
kubectl port-forward pod/parcagpu-demo-mock 9090:9090
curl -s http://localhost:9090/metrics | grep parcagpu
```

## Quick reference: local development (no Docker, no K8s)

```bash
# Build the .so locally
make local

# Run unit tests (no GPU, no BPF)
make test

# Run BPF tests with mock CUPTI (requires root, no GPU)
make test-pc-mock

# Run BPF tests with real GPU (requires root + GPU)
make test-pc-real

# Run webhook unit tests
cd deploy/webhook && go test -v ./...
```
