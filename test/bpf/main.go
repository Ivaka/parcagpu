// Copyright 2026 The Parca Authors
// SPDX-License-Identifier: Apache-2.0
//
// Test program that loads the activity_parser BPF program, attaches it
// to parcagpu USDT probes in the target shared library, and logs kernel
// activities received through the ring buffer. Also captures cubin modules
// and resolves PC addresses to source lines using llvm-dwarfdump.
//
// Usage:
//
//	go generate ./...
//	go build -o activity_parser .
//	sudo ./activity_parser -pid <PID> -lib <path/to/libparcagpucupti.so>
package main

import (
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	ebpf2 "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/parca-dev/usdt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"

	sasstable "github.com/gnurizen/sass-table"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -cflags "-I../../ebpf -I$USDT_HEADERS" activityParser activity_parser.bpf.c

// Metric definitions for the Prometheus exporter.
var (
	metricKernelDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "parcagpu_kernel_duration_seconds",
			Help:    "Duration of CUDA kernel executions in seconds.",
			Buckets: []float64{0.000001, 0.00001, 0.0001, 0.001, 0.01, 0.1, 1},
		},
		[]string{"pod", "namespace", "kernel_name", "device_id"},
	)
	metricKernelCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "parcagpu_kernel_count_total",
			Help: "Total number of CUDA kernel executions observed.",
		},
		[]string{"pod", "namespace", "kernel_name", "device_id"},
	)
	metricPCSamples = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "parcagpu_pc_samples_total",
			Help: "Total PC samples collected, by stall reason.",
		},
		[]string{"pod", "namespace", "kernel_name", "stall_reason", "device_id"},
	)
	metricGPUActive = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "parcagpu_gpu_active_seconds_total",
			Help: "Total seconds of GPU active time (sum of kernel durations) per device.",
		},
		[]string{"pod", "namespace", "device_id"},
	)
	metricEventsDropped = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "parcagpu_events_dropped_total",
			Help: "Total events dropped due to ring buffer overflow.",
		},
		[]string{"pod", "namespace"},
	)
	metricCubinsLoaded = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "parcagpu_cubins_loaded",
			Help: "Number of cubin modules currently loaded.",
		},
		[]string{"pod", "namespace"},
	)
	metricProbeAttached = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "parcagpu_probe_attached",
			Help: "1 if the probe is attached, 0 otherwise.",
		},
		[]string{"pod", "namespace", "probe_name"},
	)
	metricBPFStats = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "parcagpu_bpf_stats",
			Help: "BPF-side statistics (batches, activities, kernels, correlations, drops).",
		},
		[]string{"pod", "namespace", "stat_name"},
	)
)

func init() {
	prometheus.MustRegister(
		metricKernelDuration,
		metricKernelCount,
		metricPCSamples,
		metricGPUActive,
		metricEventsDropped,
		metricCubinsLoaded,
		metricProbeAttached,
		metricBPFStats,
	)
}

// Event type tags — must match BPF #defines.
const (
	eventTypeKernel        = 1
	eventTypeCubinLoaded   = 2
	eventTypeCubinUnloaded = 3
	eventTypePCSample      = 4
	eventTypeError         = 5
)

// KernelEvent matches struct kernel_event in the BPF program.
type KernelEvent struct {
	EventType     uint32
	_             uint32
	Start         uint64
	End           uint64
	CorrelationID uint32
	DeviceID      uint32
	StreamID      uint32
	GraphID       uint32
	GraphNodeID   uint64
	Name          [128]byte
}

// CubinEvent matches struct cubin_event in the BPF program.
type CubinEvent struct {
	EventType uint32
	_         uint32
	CubinCRC  uint64
	CubinPtr  uint64
	CubinSize uint64
}

// StallReason matches struct cupti_stall_reason in the BPF program.
type StallReason struct {
	Index   uint32
	Samples uint32
}

// ErrorEvent matches struct error_event in the BPF program.
type ErrorEvent struct {
	EventType uint32
	ErrorCode int32
	Message   [256]byte
	Component [64]byte
}

// PCSampleEvent matches struct pc_sample_event in the BPF program.
type PCSampleEvent struct {
	EventType        uint32
	StallReasonCount uint32
	CubinCRC         uint64
	PCOffset         uint64
	FunctionIndex    uint32
	CorrelationID    uint32
	FunctionName     [128]byte
	StallReasons     [64]StallReason
}

const (
	statBatches      = 0
	statActivities   = 1
	statKernels      = 2
	statDrops        = 3
	statCorrelations = 4
)

// lineEntry is a single address→source mapping from the DWARF line table.
type lineEntry struct {
	addr uint64
	file string
	line int
}

// cubinStore holds loaded cubins and their parsed line tables.
type cubinStore struct {
	mu     sync.RWMutex
	cubins map[uint64]*cubinInfo // keyed by CRC
	pid    int
}

// textSection holds one .text._Zfuncname section from the cubin ELF.
type textSection struct {
	name string
	data []byte
}

type cubinInfo struct {
	crc     uint64
	size    uint64
	lines   []lineEntry   // sorted by addr
	files   []string      // file table from line table header
	archSM  int           // SM version from ELF e_flags (e.g. 121)
	texts   []textSection // .text sections for instruction decoding
	tmpPath string        // temp file for llvm-dwarfdump
}

func newCubinStore(pid int) *cubinStore {
	return &cubinStore{
		cubins: make(map[uint64]*cubinInfo),
		pid:    pid,
	}
}

func (cs *cubinStore) load(crc, ptr, size uint64) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if _, ok := cs.cubins[crc]; ok {
		return // already loaded
	}

	data, err := readProcessMemory(cs.pid, ptr, size)
	if err != nil {
		log.Printf("  [CUBIN] failed to read cubin 0x%x (%d bytes) from pid %d: %v",
			crc, size, cs.pid, err)
		return
	}

	info := &cubinInfo{crc: crc, size: size}

	// Write to temp file for llvm-dwarfdump.
	tmp, err := os.CreateTemp("", fmt.Sprintf("cubin_%x_*.elf", crc))
	if err != nil {
		log.Printf("  [CUBIN] 0x%x loaded (%d bytes), no temp file: %v", crc, size, err)
		cs.cubins[crc] = info
		return
	}
	tmp.Write(data)
	tmp.Close()
	info.tmpPath = tmp.Name()

	// Parse line table with llvm-dwarfdump.
	lines, files, err := parseLinesWithDwarfdump(info.tmpPath)
	if err != nil {
		log.Printf("  [CUBIN] 0x%x loaded (%d bytes), no line info: %v", crc, size, err)
	} else {
		info.lines = lines
		info.files = files
		log.Printf("  [CUBIN] 0x%x loaded (%d bytes), %d line entries, %d files",
			crc, size, len(lines), len(files))
	}

	// Parse ELF to extract SM version and .text sections for SASS decoding.
	archSM, texts := parseCubinELF(data)
	info.archSM = archSM
	info.texts = texts
	if archSM > 0 {
		log.Printf("  [CUBIN] 0x%x SM%d, %d text sections", crc, archSM, len(texts))
	}

	cs.cubins[crc] = info
}

func (cs *cubinStore) unload(crc uint64) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if info, ok := cs.cubins[crc]; ok {
		if info.tmpPath != "" {
			os.Remove(info.tmpPath)
		}
		delete(cs.cubins, crc)
	}
	log.Printf("  [CUBIN] 0x%x unloaded", crc)
}

func (cs *cubinStore) cleanup() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	for _, info := range cs.cubins {
		if info.tmpPath != "" {
			os.Remove(info.tmpPath)
		}
	}
}

// resolveInstruction looks up the SASS mnemonic at a PC offset.
// Uses the sass-table opcode decoder first, falls back to nvdisasm cache.
func (cs *cubinStore) resolveInstruction(cubinCRC uint64, pcOffset uint64) string {
	cs.mu.RLock()
	info, ok := cs.cubins[cubinCRC]
	cs.mu.RUnlock()
	if !ok {
		return ""
	}

	if info.archSM == 0 || len(info.texts) == 0 {
		return ""
	}

	// pcOffset is function-relative. Try all text sections — the offset
	// should only produce a valid decode in the correct one.
	for _, ts := range info.texts {
		if int(pcOffset)+16 <= len(ts.data) {
			m := sasstable.DecodeMnemonicFromSlice(info.archSM, ts.data[pcOffset:])
			if m != "" {
				return m
			}
		}
	}
	return ""
}

// parseCubinELF extracts the SM version and .text section data from a cubin ELF.
func parseCubinELF(data []byte) (archSM int, texts []textSection) {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return 0, nil
	}
	defer f.Close()

	// Go's debug/elf doesn't expose e_flags. Read it directly from the ELF header.
	// For ELF64: e_flags is at offset 48, 4 bytes little-endian.
	if len(data) >= 52 {
		flags := binary.LittleEndian.Uint32(data[48:52])
		archSM = int((flags >> 8) & 0xFF)
	}

	for _, s := range f.Sections {
		if s.Type == elf.SHT_PROGBITS && s.Flags&elf.SHF_EXECINSTR != 0 &&
			strings.HasPrefix(s.Name, ".text") {
			d, err := s.Data()
			if err != nil {
				continue
			}
			texts = append(texts, textSection{name: s.Name, data: d})
		}
	}
	return archSM, texts
}

// resolvePC looks up a PC offset in a cubin's line table.
func (cs *cubinStore) resolvePC(cubinCRC uint64, pcOffset uint64) (file string, line int) {
	cs.mu.RLock()
	info, ok := cs.cubins[cubinCRC]
	cs.mu.RUnlock()
	if !ok || len(info.lines) == 0 {
		return
	}

	// Binary search for the largest address <= pcOffset.
	i := sort.Search(len(info.lines), func(i int) bool {
		return info.lines[i].addr > pcOffset
	})
	if i == 0 {
		return
	}
	e := info.lines[i-1]
	return e.file, e.line
}

// parseLinesWithDwarfdump runs llvm-dwarfdump --debug-line on the cubin ELF
// and parses the output into a sorted line table.
func parseLinesWithDwarfdump(path string) ([]lineEntry, []string, error) {
	cmd := exec.Command("llvm-dwarfdump", "--debug-line", path)
	out, err := cmd.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("llvm-dwarfdump: %w", err)
	}

	var entries []lineEntry
	files := map[string]bool{}
	fileList := []string{}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()

		// Parse file table entries: file_names[  N]:
		//            name: "foo.cu"
		if strings.HasPrefix(line, "           name: ") {
			name := strings.Trim(strings.TrimPrefix(line, "           name: "), "\"")
			if !files[name] {
				files[name] = true
				fileList = append(fileList, name)
			}
			continue
		}

		// Parse line table rows: 0xADDR  LINE  COL  FILE ...
		if !strings.HasPrefix(line, "0x") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		addr, err := strconv.ParseUint(strings.TrimPrefix(fields[0], "0x"), 16, 64)
		if err != nil {
			continue
		}

		lineNum, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}

		// fields[3] is the file index (1-based)
		fileIdx, err := strconv.Atoi(fields[3])
		if err != nil || fileIdx < 1 || fileIdx > len(fileList) {
			continue
		}

		entries = append(entries, lineEntry{
			addr: addr,
			file: fileList[fileIdx-1],
			line: lineNum,
		})
	}

	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("no line entries found")
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].addr < entries[j].addr
	})

	return entries, fileList, nil
}

func readProcessMemory(pid int, addr, size uint64) ([]byte, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data := make([]byte, size)
	_, err = f.ReadAt(data, int64(addr))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return data, nil
}

// podMetadata holds Kubernetes pod identity, populated from environment
// variables (set via the Downward API in the pod spec).
type podMetadata struct {
	name      string
	namespace string
}

// discoverWorkloadPID scans /proc/*/maps for a process that has the parcagpu
// shared library loaded. In a pod with shareProcessNamespace: true, all
// containers share a PID namespace, so the sidecar can see the workload's
// processes directly. Retries every 500ms for up to 60 seconds to handle
// slow-starting workloads.
func discoverWorkloadPID(libBasename string) (int, error) {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return 0, fmt.Errorf("reading /proc: %w", err)
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			pidStr := entry.Name()
			pid, err := strconv.Atoi(pidStr)
			if err != nil || pid <= 1 {
				continue
			}

			// Read /proc/<pid>/maps and check if the parcagpu .so is mapped.
			mapsData, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
			if err != nil {
				continue // process may have exited
			}
			if bytes.Contains(mapsData, []byte(libBasename)) {
				if pid == os.Getpid() {
					continue
				}
				return pid, nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return 0, fmt.Errorf("no process with %s found within 60s", libBasename)
}

func main() {
	pid := flag.Int("pid", 0, "PID of the target process")
	libPath := flag.String("lib", "", "Path to the shared library containing the USDT probe")
	verbose := flag.Bool("v", false, "Print every kernel event (default: summary only)")
	discover := flag.Bool("discover", false, "Auto-discover workload PID by scanning /proc/*/maps")
	libPathDiscover := flag.String("lib-path", "", "Path to the .so (used with -discover instead of -lib)")
	podName := flag.String("pod-name", os.Getenv("POD_NAME"), "Pod name (default: $POD_NAME env)")
	podNamespace := flag.String("pod-namespace", os.Getenv("POD_NAMESPACE"), "Pod namespace (default: $POD_NAMESPACE env)")
	metricsPort := flag.Int("metrics-port", 0, "Port for Prometheus /metrics endpoint (0 = disabled)")
	flag.Parse()

	if *discover {
		if *libPathDiscover == "" {
			flag.Usage()
			os.Exit(1)
		}
		*libPath = *libPathDiscover
	} else if *pid == 0 || *libPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	podMeta := podMetadata{name: *podName, namespace: *podNamespace}
	if *discover {
		log.Printf("Pod: %s/%s", podMeta.namespace, podMeta.name)
		log.Printf("Discovering workload PID (looking for %s in /proc/*/maps)...", filepath.Base(*libPath))
		discoveredPID, err := discoverWorkloadPID(filepath.Base(*libPath))
		if err != nil {
			log.Fatalf("PID discovery failed: %v", err)
		}
		*pid = discoveredPID
		log.Printf("Discovered workload PID: %d", *pid)
	}

	// Resolve symlinks so uprobe attaches to the correct inode.
	realLib, err := filepath.EvalSymlinks(*libPath)
	if err != nil {
		log.Fatalf("Resolving symlinks for %s: %v", *libPath, err)
	}
	if realLib != *libPath {
		log.Printf("Resolved %s -> %s", *libPath, realLib)
	}

	// Raise memlock rlimit for BPF maps.
	if err := raiseMemlock(); err != nil {
		log.Printf("Warning: failed to raise memlock rlimit: %v", err)
	}

	// Load pre-compiled BPF objects.
	objs := activityParserObjects{}
	if err := loadActivityParserObjects(&objs, nil); err != nil {
		var ve *ebpf2.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Verifier error loading BPF objects:\n%+v", ve)
		}
		log.Fatalf("Loading BPF objects: %v", err)
	}
	defer objs.Close()

	// Parse USDT probes from the shared library's .note.stapsdt section.
	probes, err := usdt.ParseProbesFromFile(realLib)
	if err != nil {
		log.Fatalf("Parsing USDT probes from %s: %v", realLib, err)
	}

	// Find USDT probes and attach uprobes at each site.
	ex, err := link.OpenExecutable(realLib)
	if err != nil {
		log.Fatalf("Opening executable %s: %v", realLib, err)
	}

	type probeTarget struct {
		name    string
		handler *ebpf2.Program
	}
	targets := []probeTarget{
		{"activity_batch", objs.HandleActivityBatch},
		{"stall_reason_map", objs.HandleStallReasonMap},
		{"cubin_loaded", objs.HandleCubinLoaded},
		{"cubin_unloaded", objs.HandleCubinUnloaded},
		{"pc_sample_batch", objs.HandlePcSampleBatch},
		{"error", objs.HandleError},
		{"cuda_correlation", objs.HandleCudaCorrelation},
	}

	var links []link.Link
	var specID uint32
	for _, t := range targets {
		for _, probe := range probes {
			if probe.Provider != "parcagpu" || probe.Name != t.name {
				continue
			}

			spec, err := usdt.ParseUSDTArguments(probe.Arguments)
			if err != nil {
				log.Fatalf("Parsing USDT args %q: %v", probe.Arguments, err)
			}

			specBytes := usdt.SpecToBytes(spec)
			if err := objs.BpfUsdtSpecs.Put(specID, specBytes); err != nil {
				log.Fatalf("Populating USDT spec map: %v", err)
			}

			cookie := uint64(specID) << 32

			log.Printf("USDT probe parcagpu:%s at offset 0x%x, args=%q, spec_id=%d",
				t.name, probe.Location, probe.Arguments, specID)

			up, err := ex.Uprobe(t.name, t.handler, &link.UprobeOptions{
				Address:      probe.Location,
				PID:          *pid,
				Cookie:       cookie,
				RefCtrOffset: probe.SemaphoreOffset,
			})
			if err != nil {
				log.Fatalf("Attaching uprobe for %s at offset 0x%x: %v", t.name, probe.Location, err)
			}
			links = append(links, up)
			specID++
		}
	}

	if len(links) == 0 {
		log.Fatalf("No parcagpu USDT probes found in %s", realLib)
	}
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	cubins := newCubinStore(*pid)
	defer cubins.cleanup()

	// Stall reason index → name cache, populated lazily from BPF map.
	stallReasonNames := map[uint32]string{}

	// Export probe attachment as metrics.
	for _, t := range targets {
		metricProbeAttached.WithLabelValues(podMeta.name, podMeta.namespace, t.name).Set(1)
	}

	// Start Prometheus metrics server if requested.
	if *metricsPort > 0 {
		go func() {
			http.Handle("/metrics", promhttp.Handler())
			addr := fmt.Sprintf(":%d", *metricsPort)
			log.Printf("Prometheus metrics server listening on %s/metrics", addr)
			if err := http.ListenAndServe(addr, nil); err != nil {
				log.Printf("Metrics server error: %v", err)
			}
		}()
	}

	// Open ring buffer reader.
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Opening ring buffer: %v", err)
	}
	defer rd.Close()

	// Handle signals.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	done := make(chan struct{})
	go func() {
		for {
			if err := syscall.Kill(*pid, 0); err != nil {
				log.Printf("Target process %d exited", *pid)
				close(done)
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()

	go func() {
		select {
		case <-sig:
		case <-done:
		}
		rd.Close()
	}()

	log.Printf("Attached %d USDT probe(s) in %s (PID %d)", len(links), realLib, *pid)
	log.Printf("Waiting for events...")

	var eventCount uint64
	var pcSampleCount uint64
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			printStats(&objs, eventCount, podMeta)
		}
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("Reading from ring buffer: %v", err)
			continue
		}

		raw := record.RawSample
		if len(raw) < 4 {
			continue
		}

		eventType := binary.LittleEndian.Uint32(raw[:4])

		switch eventType {
		case eventTypeKernel:
			var event KernelEvent
			if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err != nil {
				log.Printf("Parsing kernel event: %v", err)
				continue
			}
			eventCount++
			name := cString(event.Name[:])
			duration := event.End - event.Start
			if *verbose {
				fmt.Printf("kernel: name=%-40s corr=%-6d dev=%d stream=%d graph=%-3d duration=%dns\n",
					name, event.CorrelationID, event.DeviceID, event.StreamID, event.GraphID, duration)
			}
			// Export metrics.
			metricKernelDuration.WithLabelValues(
				podMeta.name, podMeta.namespace, name,
				strconv.FormatUint(uint64(event.DeviceID), 10),
			).Observe(float64(duration) / 1e9)
			metricKernelCount.WithLabelValues(
				podMeta.name, podMeta.namespace, name,
				strconv.FormatUint(uint64(event.DeviceID), 10),
			).Inc()
			metricGPUActive.WithLabelValues(
				podMeta.name, podMeta.namespace,
				strconv.FormatUint(uint64(event.DeviceID), 10),
			).Add(float64(duration) / 1e9)

		case eventTypeCubinLoaded:
			var event CubinEvent
			if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err != nil {
				log.Printf("Parsing cubin event: %v", err)
				continue
			}
			cubins.load(event.CubinCRC, event.CubinPtr, event.CubinSize)
			metricCubinsLoaded.WithLabelValues(podMeta.name, podMeta.namespace).Inc()

		case eventTypeCubinUnloaded:
			var event CubinEvent
			if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err != nil {
				log.Printf("Parsing cubin event: %v", err)
				continue
			}
			cubins.unload(event.CubinCRC)
			metricCubinsLoaded.WithLabelValues(podMeta.name, podMeta.namespace).Dec()

		case eventTypeError:
			var event ErrorEvent
			if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err != nil {
				log.Printf("Parsing error event: %v", err)
				continue
			}
			msg := cString(event.Message[:])
			comp := cString(event.Component[:])
			log.Printf("ERROR [%s] code=%d: %s", comp, event.ErrorCode, msg)

		case eventTypePCSample:
			var event PCSampleEvent
			if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event); err != nil {
				log.Printf("Parsing pc sample event: %v", err)
				continue
			}
			pcSampleCount++

			// Lazily populate stall reason name cache.
			if len(stallReasonNames) == 0 {
				for i := uint32(0); i < 64; i++ {
					var name [64]byte
					if err := objs.StallReasons.Lookup(&i, &name); err != nil {
						continue
					}
					s := cString(name[:])
					if s != "" {
						stallReasonNames[i] = s
					}
				}
			}

			name := cString(event.FunctionName[:])
			file, line := cubins.resolvePC(event.CubinCRC, event.PCOffset)
			insn := cubins.resolveInstruction(event.CubinCRC, event.PCOffset)

			src := ""
			if file != "" {
				src = fmt.Sprintf("  %s:%d", file, line)
			}
			insnStr := ""
			if insn != "" {
				insnStr = fmt.Sprintf("  [%s]", insn)
			}
			corrStr := ""
			if event.CorrelationID != 0 {
				corrStr = fmt.Sprintf("  corr=%d", event.CorrelationID)
			}
			fmt.Printf("pc_sample: %s  pc=0x%04x%s%s%s\n", name, event.PCOffset, src, insnStr, corrStr)
			for i := uint32(0); i < event.StallReasonCount; i++ {
				sr := event.StallReasons[i]
				if sr.Samples == 0 {
					continue
				}
				srName := stallReasonNames[sr.Index]
				if srName == "" {
					srName = fmt.Sprintf("reason[%d]", sr.Index)
				}
				fmt.Printf("    %s = %d\n", srName, sr.Samples)
				metricPCSamples.WithLabelValues(
					podMeta.name, podMeta.namespace, name, srName, "",
				).Add(float64(sr.Samples))
			}
		}
	}

	fmt.Println()
	log.Printf("Final stats:")
	printStats(&objs, eventCount, podMeta)
	log.Printf("  pc_samples=%d", pcSampleCount)
	printStallReasonMap(&objs)
	printCubins(cubins)
}

func printStats(objs *activityParserObjects, eventCount uint64, podMeta podMetadata) {
	var batches, activities, kernels, drops, correlations uint64
	batchKey := uint32(statBatches)
	activityKey := uint32(statActivities)
	kernelKey := uint32(statKernels)
	dropsKey := uint32(statDrops)
	corrKey := uint32(statCorrelations)

	objs.Stats.Lookup(&batchKey, &batches)
	objs.Stats.Lookup(&activityKey, &activities)
	objs.Stats.Lookup(&kernelKey, &kernels)
	objs.Stats.Lookup(&dropsKey, &drops)
	objs.Stats.Lookup(&corrKey, &correlations)

	log.Printf("  batches=%d activities_scanned=%d kernels_found=%d events_received=%d drops=%d correlations=%d",
		batches, activities, kernels, eventCount, drops, correlations)

	// Export BPF stats as Prometheus metrics.
	metricBPFStats.WithLabelValues(podMeta.name, podMeta.namespace, "batches").Set(float64(batches))
	metricBPFStats.WithLabelValues(podMeta.name, podMeta.namespace, "activities_scanned").Set(float64(activities))
	metricBPFStats.WithLabelValues(podMeta.name, podMeta.namespace, "kernels_found").Set(float64(kernels))
	metricBPFStats.WithLabelValues(podMeta.name, podMeta.namespace, "drops").Set(float64(drops))
	metricBPFStats.WithLabelValues(podMeta.name, podMeta.namespace, "correlations").Set(float64(correlations))
	metricEventsDropped.WithLabelValues(podMeta.name, podMeta.namespace).Add(float64(drops))
}

func printStallReasonMap(objs *activityParserObjects) {
	var loaded uint32
	loadedKey := uint32(0)
	if err := objs.StallMapLoaded.Lookup(&loadedKey, &loaded); err != nil || loaded == 0 {
		log.Printf("  stall reason map: not received")
		return
	}

	log.Printf("  stall reason map:")
	for i := uint32(0); i < 64; i++ {
		var name [64]byte
		if err := objs.StallReasons.Lookup(&i, &name); err != nil {
			continue
		}
		s := cString(name[:])
		if s == "" {
			continue
		}
		log.Printf("    [%2d] %s", i, s)
	}
}

func printCubins(cs *cubinStore) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	if len(cs.cubins) == 0 {
		log.Printf("  cubins: none loaded")
		return
	}

	log.Printf("  cubins loaded: %d", len(cs.cubins))
	for crc, info := range cs.cubins {
		log.Printf("    crc=0x%x size=%d lines=%d files=%v",
			crc, info.size, len(info.lines), info.files)

		// Print first 10 line entries as demo.
		for i, e := range info.lines {
			if i >= 10 {
				log.Printf("      ... and %d more entries", len(info.lines)-10)
				break
			}
			log.Printf("      0x%04x -> %s:%d", e.addr, e.file, e.line)
		}
	}
}

func raiseMemlock() error {
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// Ensure struct sizes match BPF.
var _ = [1]struct{}{}[unsafe.Sizeof(KernelEvent{})-176]
var _ = [1]struct{}{}[unsafe.Sizeof(CubinEvent{})-32]
var _ = [1]struct{}{}[unsafe.Sizeof(PCSampleEvent{})-672]
