//go:build linux

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/detectsink"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/ebpf"
	detectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/detect"
)

// TestDetectionPipelineEndToEndOnKernel wires the REAL eBPF sensor to the engine and the file sink —
// the exact composition the agent uses — and proves the whole Phase-3 chain on a live kernel: a real
// `ps` exec is captured, matched into det.process_enumeration, and written to the JSONL sink. Skips
// unless root (unprivileged eBPF is disabled).
func TestDetectionPipelineEndToEndOnKernel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("detection pipeline needs root (unprivileged eBPF is disabled); run under sudo")
	}
	dir := t.TempDir()
	sinkPath := filepath.Join(dir, "detections.jsonl")
	sink, err := detectsink.New(sinkPath)
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	sensor := ebpf.NewSensor("host-it", "agent:it", detection.Classes())
	eng, err := detectuc.NewEngine(sensor, sink, "host-it", "agent:it", detectuc.Options{})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx) }()

	time.Sleep(500 * time.Millisecond) // let the sensor attach
	// Generate fixtures until the detection lands or we time out.
	found := false
	deadline := time.After(6 * time.Second)
	for !found {
		_ = exec.Command("ps", "-ef").Run()
		select {
		case <-deadline:
			cancel()
			<-done
			_ = sink.Close()
			t.Fatal("no det.process_enumeration written to the sink within the window")
		case <-time.After(300 * time.Millisecond):
		}
		found = sinkHasRule(t, sinkPath, "det.process_enumeration")
	}

	cancel()
	<-done
	if err := sink.Close(); err != nil {
		t.Errorf("sink close: %v", err)
	}
	// Every written line must be a valid, fully-attributed detection.
	for _, d := range readDetections(t, sinkPath) {
		if err := d.Validate(); err != nil {
			t.Errorf("sink wrote an invalid detection: %v", err)
		}
	}
}

func sinkHasRule(t *testing.T, path, ruleID string) bool {
	t.Helper()
	for _, d := range readDetections(t, path) {
		if d.RuleID == ruleID {
			return true
		}
	}
	return false
}

func readDetections(t *testing.T, path string) []detection.Detection {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []detection.Detection
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		var d detection.Detection
		if json.Unmarshal(sc.Bytes(), &d) == nil {
			out = append(out, d)
		}
	}
	return out
}
