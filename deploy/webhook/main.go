// Copyright 2026 The Parca Authors
// SPDX-License-Identifier: Apache-2.0

// Command parcagpu-webhook is a mutating admission webhook that injects
// the parcagpu GPU profiling infrastructure into pods labeled
// parcagpu.dev/enabled: "true".
//
// The webhook patches the pod spec to:
//   - Set shareProcessNamespace: true (so the observer sidecar can see the
//     workload's PID namespace and attach uprobes)
//   - Add an emptyDir volume for the .so
//   - Add an init container that copies libparcagpucupti.so from the
//     ghcr.io/parca-dev/parcagpu image
//   - Set CUDA_INJECTION64_PATH on every existing container
//   - Add the observer sidecar container (privileged, with metrics port)
//   - Add Prometheus scrape annotations
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

const (
	// Label that triggers injection.
	injectLabel = "parcagpu.dev/enabled"

	// Value the label must have to trigger injection.
	injectValue = "true"

	// Volume name for the shared .so mount.
	libVolumeName = "parcagpu-lib"

	// Path where the .so is mounted in containers.
	libMountPath = "/parcagpu"

	// .so filename.
	libFilename = "libparcagpucupti.so"

	// Init container name.
	initContainerName = "parcagpu-init"

	// Sidecar container name.
	sidecarName = "parcagpu-observer"

	// Default image references (overridable via flags).
	defaultLibImage   = "ghcr.io/parca-dev/parcagpu:latest"
	defaultObsImage   = "ghcr.io/parca-dev/parcagpu-observer:latest"
	defaultMetricsPort = 9090
)

// AdmissionReview mirrors the Kubernetes admission review object.
// We define minimal structs rather than importing k8s.io/api to keep
// the webhook dependency-free.
type AdmissionReview struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Request    struct {
		UID string `json:"uid"`
		Kind struct {
			Group   string `json:"group"`
			Version string `json:"version"`
			Kind    string `json:"kind"`
		} `json:"kind"`
		Resource struct {
			Group    string `json:"group"`
			Version  string `json:"version"`
			Resource string `json:"resource"`
		} `json:"resource"`
		Name      string                 `json:"name"`
		Namespace string                 `json:"namespace"`
		Operation string                 `json:"operation"`
		UserInfo  map[string]interface{} `json:"userInfo"`
		Object    json.RawMessage        `json:"object"`
	} `json:"request"`
}

// AdmissionResponse is the response sent back to the API server.
type AdmissionResponse struct {
	APIVersion string       `json:"apiVersion"`
	Kind       string       `json:"kind"`
	Response   struct {
		UID     string `json:"uid"`
		Allowed bool   `json:"allowed"`
		Patch   []byte `json:"patch,omitempty"`
		PatchType string `json:"patchType,omitempty"`
	} `json:"response"`
}

// podSpec is a minimal extraction of the Kubernetes PodSpec for JSON patching.
type podMeta struct {
	Labels map[string]string `json:"labels,omitempty"`
}

type podObject struct {
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	Metadata   podMeta                `json:"metadata"`
	Spec       map[string]interface{} `json:"spec"`
}

// JSONPatch operation.
type jsonPatch struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

// Config holds the webhook's runtime configuration.
type Config struct {
	LibImage      string
	ObserverImage string
	MetricsPort   int
	ImagePullSecret string
}

func main() {
	cert := flag.String("cert", "/certs/tls.crt", "TLS certificate path")
	key := flag.String("key", "/certs/tls.key", "TLS private key path")
	port := flag.Int("port", 8443, "HTTPS listen port")
	libImage := flag.String("lib-image", defaultLibImage, "Image containing libparcagpucupti.so for the init container")
	obsImage := flag.String("observer-image", defaultObsImage, "Observer sidecar image")
	metricsPort := flag.Int("metrics-port", defaultMetricsPort, "Prometheus metrics port in the sidecar")
	imagePullSecret := flag.String("image-pull-secret", "", "Name of a Kubernetes Secret (docker-registry type) to inject into pods for pulling images. Empty = no secret.")
	flag.Parse()

	cfg := Config{
		LibImage:      *libImage,
		ObserverImage: *obsImage,
		MetricsPort:   *metricsPort,
		ImagePullSecret: *imagePullSecret,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", func(w http.ResponseWriter, r *http.Request) {
		handleMutate(w, r, cfg)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("parcagpu-webhook listening on %s", addr)

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	if err := server.ListenAndServeTLS(*cert, *key); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func handleMutate(w http.ResponseWriter, r *http.Request, cfg Config) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading body: %v", err)
		http.Error(w, "read body error", http.StatusBadRequest)
		return
	}

	var review AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		log.Printf("Error unmarshaling admission review: %v", err)
		http.Error(w, "unmarshal error", http.StatusBadRequest)
		return
	}

	// Only mutate on CREATE.
	if review.Request.Operation != "CREATE" {
		respond(w, review.Request.UID, true, nil)
		return
	}

	// Parse the pod object.
	var pod podObject
	if err := json.Unmarshal(review.Request.Object, &pod); err != nil {
		log.Printf("Error unmarshaling pod object: %v", err)
		http.Error(w, "unmarshal pod error", http.StatusBadRequest)
		return
	}

	// Check for the injection label.
	if pod.Metadata.Labels[injectLabel] != injectValue {
		// Not labeled — no mutation.
		respond(w, review.Request.UID, true, nil)
		return
	}

	// Build the JSON patch.
	patch := buildPatch(&pod, cfg, review.Request.Namespace)

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		log.Printf("Error marshaling patch: %v", err)
		http.Error(w, "marshal patch error", http.StatusInternalServerError)
		return
	}

	respond(w, review.Request.UID, true, patchBytes)
	log.Printf("Injected parcagpu into pod %s/%s (uid=%s)", review.Request.Namespace, review.Request.Name, review.Request.UID)
}

// buildPatch constructs the JSON patch operations for injection.
func buildPatch(pod *podObject, cfg Config, namespace string) []jsonPatch {
	var patch []jsonPatch

	// 1. Set shareProcessNamespace: true.
	patch = append(patch, jsonPatch{
		Op:    "add",
		Path:  "/spec/shareProcessNamespace",
		Value: true,
	})

	// 2. Add the emptyDir volume for the .so (if not already present).
	volumes := getSlice(pod.Spec, "volumes")
	hasLibVolume := false
	for _, v := range volumes {
		if m, ok := v.(map[string]interface{}); ok {
			if m["name"] == libVolumeName {
				hasLibVolume = true
				break
			}
		}
	}
	if !hasLibVolume {
		patch = append(patch, jsonPatch{
			Op:   "add",
			Path: "/spec/volumes/-",
			Value: map[string]interface{}{
				"name": libVolumeName,
				"emptyDir": map[string]interface{}{},
			},
		})
	}

	// 3. Add the init container.
	initContainer := map[string]interface{}{
		"name":  initContainerName,
		"image": cfg.LibImage,
		"command": []string{
			"sh", "-c",
			fmt.Sprintf("for src in /usr/lib/%s /test/build/lib/%s; do [ -f \"$src\" ] && cp \"$src\" %s/%s && break; done && [ -f %s/%s ] || { echo 'ERROR: %s not found in init container image' >&2; exit 1; }", libFilename, libFilename, libMountPath, libFilename, libMountPath, libFilename, libFilename),
		},
		"volumeMounts": []map[string]interface{}{
			{
				"name":      libVolumeName,
				"mountPath": libMountPath,
			},
		},
	}
	patch = append(patch, jsonPatch{
		Op:    "add",
		Path:  "/spec/initContainers/-",
		Value: initContainer,
	})

	// 4. For each existing container, add the volume mount and env var.
	containers := getSlice(pod.Spec, "containers")
	for i := range containers {
		mountPath := fmt.Sprintf("/spec/containers/%d/volumeMounts/-", i)
		envPath := fmt.Sprintf("/spec/containers/%d/env/-", i)

		// Ensure volumeMounts array exists by adding the first element.
		// Kubernetes patches: if the array doesn't exist, "add" to "-" creates it.
		patch = append(patch, jsonPatch{
			Op:   "add",
			Path: mountPath,
			Value: map[string]interface{}{
				"name":      libVolumeName,
				"mountPath": libMountPath,
			},
		})

		patch = append(patch, jsonPatch{
			Op:   "add",
			Path: envPath,
			Value: map[string]interface{}{
				"name":  "CUDA_INJECTION64_PATH",
				"value": fmt.Sprintf("%s/%s", libMountPath, libFilename),
			},
		})
	}

	// 5. Add the observer sidecar container.
	sidecar := map[string]interface{}{
		"name":  sidecarName,
		"image": cfg.ObserverImage,
		"args": []string{
			"-discover",
			"-lib-path", fmt.Sprintf("%s/%s", libMountPath, libFilename),
			"-metrics-port", fmt.Sprintf("%d", cfg.MetricsPort),
		},
		"env": []map[string]interface{}{
			{
				"name": "POD_NAME",
				"valueFrom": map[string]interface{}{
					"fieldRef": map[string]interface{}{
						"fieldPath": "metadata.name",
					},
				},
			},
			{
				"name": "POD_NAMESPACE",
				"valueFrom": map[string]interface{}{
					"fieldRef": map[string]interface{}{
						"fieldPath": "metadata.namespace",
					},
				},
			},
		},
		"volumeMounts": []map[string]interface{}{
			{
				"name":      libVolumeName,
				"mountPath": libMountPath,
			},
		},
		"ports": []map[string]interface{}{
			{
				"containerPort": cfg.MetricsPort,
				"name":          "metrics",
			},
		},
		"securityContext": map[string]interface{}{
			"privileged": true,
		},
	}
	patch = append(patch, jsonPatch{
		Op:    "add",
		Path:  "/spec/containers/-",
		Value: sidecar,
	})

	// 6. Add Prometheus scrape annotations.
	patch = append(patch, jsonPatch{
		Op:   "add",
		Path: "/metadata/annotations",
		Value: map[string]interface{}{
			"prometheus.io/scrape": "true",
			"prometheus.io/port":   fmt.Sprintf("%d", cfg.MetricsPort),
		},
	})

	// 7. Add imagePullSecrets if configured.
	if cfg.ImagePullSecret != "" {
		patch = append(patch, jsonPatch{
			Op:   "add",
			Path: "/spec/imagePullSecrets",
			Value: []map[string]interface{}{
				{"name": cfg.ImagePullSecret},
			},
		})
	}

	return patch
}

// getSlice extracts a []interface{} from a map key, returning nil if absent.
func getSlice(m map[string]interface{}, key string) []interface{} {
	v, ok := m[key]
	if !ok {
		return nil
	}
	s, ok := v.([]interface{})
	if !ok {
		return nil
	}
	return s
}

func respond(w http.ResponseWriter, uid string, allowed bool, patch []byte) {
	resp := AdmissionResponse{}
	resp.APIVersion = "admission.k8s.io/v1"
	resp.Kind = "AdmissionReview"
	resp.Response.UID = uid
	resp.Response.Allowed = allowed
	if patch != nil {
		resp.Response.Patch = patch
		patchType := "JSONPatch"
		resp.Response.PatchType = patchType
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// init generates a self-signed TLS certificate at startup if the cert files
// are not present. This simplifies development — in production, cert files
// are mounted via a Kubernetes secret.
func init() {
	if os.Getenv("PARCAGPU_WEBHOOK_AUTOCERT") == "1" {
		if err := generateSelfSignedCert(); err != nil {
			log.Fatalf("Failed to generate self-signed cert: %v", err)
		}
	}
}
