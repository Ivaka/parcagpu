# Parcagpu Kubernetes Deployment

Deploy parcagpu GPU observability to any Kubernetes cluster. Pods labeled
`parcagpu.dev/enabled: "true"` are automatically instrumented with
CUPTI profiling via an admission webhook — no code changes required.

## Architecture

```
Pod (labeled parcagpu.dev/enabled=true)
├── init container (copies libparcagpucupti.so to emptyDir)
├── workload container (CUDA_INJECTION64_PATH set by webhook)
└── observer sidecar (privileged, attaches eBPF uprobes, exports /metrics)
        │
        ▼
  Prometheus → Grafana dashboard
```

## Quick Start

### 1. Build and push images

```bash
# The .so library image (already published to ghcr.io/parca-dev/parcagpu)
make docker-push

# The observer sidecar image
make docker-push-observer

# The webhook image
docker build -f deploy/webhook/Dockerfile -t ghcr.io/parca-dev/parcagpu-webhook:latest deploy/webhook/
docker push ghcr.io/parca-dev/parcagpu-webhook:latest
```

### 2. Deploy to Kubernetes

```bash
kubectl apply -f deploy/k8s/
```

This deploys:
- Mutating admission webhook (Deployment + Service + MutatingWebhookConfiguration)
- TLS cert generation Job
- Prometheus scrape config / PodMonitor
- Grafana with pre-built parcagpu dashboard

### 3. Label your CUDA workload

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-cuda-app
  labels:
    parcagpu.dev/enabled: "true"   # <-- this triggers injection
spec:
  containers:
    - name: app
      image: my-cuda-image:latest
      resources:
        limits:
          nvidia.com/gpu: 1
```

The webhook automatically:
- Sets `CUDA_INJECTION64_PATH=/parcagpu/libparcagpucupti.so`
- Adds an init container that copies the `.so`
- Adds the observer sidecar with Prometheus metrics on port 9090
- Sets `shareProcessNamespace: true` (so the observer can see the workload PID)
- Adds Prometheus scrape annotations

### 4. View metrics

```bash
# Port-forward to Grafana
kubectl port-forward svc/parcagpu-grafana 3000:3000

# Open http://localhost:3000
```

Or query metrics directly:
```bash
kubectl port-forward pod/my-cuda-app 9090:9090
curl http://localhost:9090/metrics | grep parcagpu
```

## Demo Workloads

Two demo workloads are included:

### Mock (no GPU required)

```bash
kubectl apply -f deploy/k8s/demo-workload-mock.yaml
```

Runs `test_cupti_prof` with mock CUPTI/CUDA libraries — demonstrates the full
pipeline (kernel events, PC sampling, stall reasons, cubin loading) on any
cluster without GPU hardware.

### Real GPU

```bash
kubectl apply -f deploy/k8s/demo-workload-gpu.yaml
```

Runs a real CUDA microbenchmark with PC sampling enabled. Requires a node with
an NVIDIA GPU and the NVIDIA device plugin.

## Prometheus Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `parcagpu_kernel_duration_seconds` | histogram | pod, namespace, kernel_name, device_id | CUDA kernel execution duration |
| `parcagpu_kernel_count_total` | counter | pod, namespace, kernel_name, device_id | Total kernels observed |
| `parcagpu_pc_samples_total` | counter | pod, namespace, kernel_name, stall_reason, device_id | PC samples by stall reason |
| `parcagpu_gpu_active_seconds_total` | counter | pod, namespace, device_id | GPU active time (sum of kernel durations) |
| `parcagpu_events_dropped_total` | counter | pod, namespace | Ring buffer overflow drops |
| `parcagpu_cubins_loaded` | gauge | pod, namespace | Currently loaded cubin modules |
| `parcagpu_probe_attached` | gauge | pod, namespace, probe_name | 1 per attached USDT probe |
| `parcagpu_bpf_stats` | gauge | pod, namespace, stat_name | BPF-side statistics |

## Environment Variables

The observer sidecar reads these from the Downward API:

| Variable | Source | Description |
|----------|--------|-------------|
| `POD_NAME` | `metadata.name` | Pod name (for metric labels) |
| `POD_NAMESPACE` | `metadata.namespace` | Pod namespace (for metric labels) |

The workload container gets:
| Variable | Value | Description |
|----------|-------|-------------|
| `CUDA_INJECTION64_PATH` | `/parcagpu/libparcagpucupti.so` | CUDA injection library path |

## Observer CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-discover` | false | Auto-discover workload PID via /proc/*/maps scan |
| `-lib-path` | (required with -discover) | Path to the .so in the shared volume |
| `-pod-name` | `$POD_NAME` | Pod name for metric labels |
| `-pod-namespace` | `$POD_NAMESPACE` | Pod namespace for metric labels |
| `-metrics-port` | 0 (disabled) | Port for Prometheus /metrics endpoint |
| `-pid` | 0 | Explicit PID (manual mode, not -discover) |
| `-lib` | (required with -pid) | Path to the .so (manual mode) |
| `-v` | false | Print every kernel event |

## Files

```
deploy/
├── k8s/
│   ├── webhook-rbac.yaml          # ServiceAccount, ClusterRole, Binding
│   ├── webhook-config.yaml        # MutatingWebhookConfiguration
│   ├── webhook-deployment.yaml    # Webhook Deployment + Service
│   ├── webhook-tls-job.yaml       # TLS cert generation Job
│   ├── prometheus-config.yaml     # Scrape config + PodMonitor
│   ├── grafana-deployment.yaml    # Grafana with dashboard
│   ├── demo-workload-mock.yaml    # Mock demo (no GPU)
│   ├── demo-workload-gpu.yaml     # Real GPU demo
│   └── test-e2e.sh               # End-to-end test script
├── grafana/
│   ├── dashboard.json             # Full Grafana dashboard JSON
│   └── datasource.yaml            # Prometheus datasource
└── webhook/
    ├── main.go                    # Webhook server
    ├── tls.go                     # Self-signed cert generation
    ├── webhook_test.go            # Unit tests
    ├── Dockerfile                 # Webhook container image
    └── go.mod                     # Go module
```
