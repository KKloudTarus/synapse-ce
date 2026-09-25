package secretscan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchperf"
)

// The pinned workload is compared with the committed allocation ceiling.
// Latency and throughput are compared with a same-runner control in hosted CI.

const (
	perfSamples = 30
	perfWarmup  = 5
	// perfWorkloadFiles fixes the workload size so the scanned bytes are stable across runs and platforms.
	perfWorkloadFiles = 40
	perfBaselinePath  = "../../../../docs/benchmarks/secretscan-perf.json"
)

// writePerfWorkload writes perfWorkloadFiles files, each the concatenated labeled corpus lines, so the scanned
// bytes are stable across runs and platforms. It returns the dataset digest of the fixture (the block content
// plus the file count) so the gate can assert its live workload matches the committed baseline.
func writePerfWorkload(t *testing.T, dir string) (datasetDigest string) {
	t.Helper()
	corpus := buildSecretsCorpus()
	var block string
	for _, c := range corpus {
		block += c.value + "\n"
	}
	for i := 0; i < perfWorkloadFiles; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%02d.txt", i)), []byte(block), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return benchperf.DatasetDigest("files", fmt.Sprintf("%d", perfWorkloadFiles), "block", block)
}

func TestSecretScanPerfGate(t *testing.T) {
	if testing.Short() {
		t.Skip("perf gate skipped in -short")
	}
	dir := t.TempDir()
	datasetDigest := writePerfWorkload(t, dir)
	scanner := New()
	scan := func() {
		if _, err := scanner.ScanFiles(context.Background(), dir); err != nil {
			t.Fatalf("scan: %v", err)
		}
	}

	res := benchperf.Measure(perfWarmup, perfSamples, scan)
	if err := benchperf.CheckPeakEvidence(res); err != nil {
		t.Fatal(err)
	}
	env := benchperf.EnvironmentDigest()
	t.Logf("secretscan perf: release=%s env=%s samples=%d alloc_bytes(median)=%d peak_mem=%d latency_p50=%s latency_p95=%s dataset=%s throughput_ops_per_second=%.6f",
		benchperf.ReleaseDigest(), env, perfSamples, res.MedianAllocBytes, res.PeakMemoryBytes, res.LatencyP50, res.LatencyP95, datasetDigest, res.ThroughputOpsPerSecond)

	base, found, err := benchperf.Load(perfBaselinePath, perfWarmup, perfSamples)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		// A missing baseline must fail, not silently disable the gate: the committed baseline is what the
		// ratchet consumes, so its absence is a broken gate, not a pass.
		t.Fatalf("no committed baseline at %s: the performance ratchet is disabled (commit the measured baseline)", perfBaselinePath)
	}
	if datasetDigest != base.DatasetDigest {
		t.Fatalf("fixture drift: workload digest %s != committed %s (the measured workload changed)", datasetDigest, base.DatasetDigest)
	}
	ceil := base.AllocCeilingBytes
	if res.MedianAllocBytes > ceil {
		t.Errorf("secretscan allocations regressed: median %d bytes exceeds committed ceiling %d",
			res.MedianAllocBytes, ceil)
	}
	if base.EnvironmentDigest == env {
		t.Logf("latency vs same-environment baseline: p50 %s (baseline %dms), p95 %s (baseline %dms)",
			res.LatencyP50, base.LatencyP50Millis, res.LatencyP95, base.LatencyP95Millis)
	} else {
		t.Logf("latency not gated: current environment %s differs from baseline %s", env, base.EnvironmentDigest)
	}
}
