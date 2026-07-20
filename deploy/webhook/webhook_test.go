// Copyright 2026 The Parca Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// rawPod is a minimal pod spec for testing — we use string keys to avoid
// importing k8s.io/api.
const labeledPod = `{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "cuda-app",
    "namespace": "default",
    "labels": {
      "parcagpu.dev/enabled": "true"
    }
  },
  "spec": {
    "containers": [
      {
        "name": "app",
        "image": "my-cuda-app:latest"
      }
    ]
  }
}`

const unlabeledPod = `{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "plain-app",
    "namespace": "default",
    "labels": {}
  },
  "spec": {
    "containers": [
      {
        "name": "app",
        "image": "my-app:latest"
      }
    ]
  }
}`

func parsePod(t *testing.T, raw string) *podObject {
	t.Helper()
	var pod podObject
	if err := json.Unmarshal([]byte(raw), &pod); err != nil {
		t.Fatalf("unmarshal pod: %v", err)
	}
	return &pod
}

func TestBuildPatchLabeledPod(t *testing.T) {
	pod := parsePod(t, labeledPod)
	cfg := Config{
		LibImage:     "ghcr.io/parca-dev/parcagpu:latest",
		ObserverImage: "ghcr.io/parca-dev/parcagpu-observer:latest",
		MetricsPort:  9090,
	}

	patch := buildPatch(pod, cfg, "default")
	if len(patch) == 0 {
		t.Fatal("expected non-empty patch for labeled pod")
	}

	// Verify the patch contains the key operations by serializing to JSON.
	raw, _ := json.Marshal(patch)
	patchStr := string(raw)

	checks := []string{
		"/spec/shareProcessNamespace",     // PID namespace sharing
		libVolumeName,                      // emptyDir volume
		initContainerName,                  // init container
		sidecarName,                        // observer sidecar
		"CUDA_INJECTION64_PATH",           // env var on workload
		"/metadata/annotations",           // Prometheus annotations
		"prometheus.io/scrape",
		"-discover",                        // observer discover mode
	}

	for _, expected := range checks {
		if !strings.Contains(patchStr, expected) {
			t.Errorf("patch missing %q\npatch: %s", expected, patchStr)
		}
	}
}

func TestBuildPatchUnlabeledPod(t *testing.T) {
	pod := parsePod(t, unlabeledPod)
	cfg := Config{MetricsPort: 9090}

	// buildPatch still builds a patch, but the caller (handleMutate) checks
	// the label and skips calling buildPatch. Here we just verify the function
	// doesn't panic on a pod with no labels.
	patch := buildPatch(pod, cfg, "default")
	if len(patch) == 0 {
		t.Fatal("expected non-empty patch even for unlabeled pod (caller filters)")
	}
}

func TestBuildPatchMultipleContainers(t *testing.T) {
	multiPod := `{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "multi",
    "labels": {"parcagpu.dev/enabled": "true"}
  },
  "spec": {
    "containers": [
      {"name": "app1", "image": "img1"},
      {"name": "app2", "image": "img2"}
    ]
  }
}`
	pod := parsePod(t, multiPod)
	cfg := Config{MetricsPort: 9090}

	patch := buildPatch(pod, cfg, "default")
	raw, _ := json.Marshal(patch)
	patchStr := string(raw)

	// Each container should get a CUDA_INJECTION64_PATH env var.
	// There should be 2 occurrences (one per container).
	count := strings.Count(patchStr, "CUDA_INJECTION64_PATH")
	if count != 2 {
		t.Errorf("expected 2 CUDA_INJECTION64_PATH env vars, got %d", count)
	}
}

func TestBuildPatchIdempotentVolume(t *testing.T) {
	// Pod that already has the parcagpu-lib volume.
	podWithVol := `{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "already",
    "labels": {"parcagpu.dev/enabled": "true"}
  },
  "spec": {
    "volumes": [
      {"name": "parcagpu-lib", "emptyDir": {}}
    ],
    "containers": [
      {"name": "app", "image": "img"}
    ]
  }
}`
	pod := parsePod(t, podWithVol)
	cfg := Config{MetricsPort: 9090}

	patch := buildPatch(pod, cfg, "default")
	raw, _ := json.Marshal(patch)
	patchStr := string(raw)

	// Should NOT add another volume entry since it already exists.
	// Count occurrences of "parcagpu-lib" in volume context (not volumeMounts).
	// The volume add path is "/spec/volumes/-" — we should not see it added again.
	volAdds := strings.Count(patchStr, `"/spec/volumes/-"`)
	if volAdds > 0 {
		t.Errorf("expected no volume add (already exists), got %d\npatch: %s", volAdds, patchStr)
	}
}

func TestBuildPatchAnnotations(t *testing.T) {
	pod := parsePod(t, labeledPod)
	cfg := Config{MetricsPort: 9090}

	patch := buildPatch(pod, cfg, "default")
	raw, _ := json.Marshal(patch)
	patchStr := string(raw)

	if !strings.Contains(patchStr, "prometheus.io/scrape") {
		t.Error("missing prometheus.io/scrape annotation")
	}
	if !strings.Contains(patchStr, "9090") {
		t.Error("missing metrics port in annotation")
	}
}
