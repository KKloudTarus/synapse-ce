package secretscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"
)

// perf_test.go is the owned secret-scan performance gate (#1040 A6). It measures repeated scans of a pinned
// workload and ratchets on BYTES ALLOCATED per scan. Allocation is deterministic for a given Go toolchain and
// input (it does not depend on CPU count or clock speed), so unlike wall-clock latency it gives a stable
// cross-machine regression signal; the generous 30% tolerance absorbs the small differences a different Go
// minor version can introduce, while catching a real regression (a leak or an added copy that inflates
// allocations). Wall-clock latency (median/p95) IS CPU-dependent, so it is only recorded, and compared to the
// baseline only within the same environment. The baseline lives at docs/benchmarks/secretscan-perf.json and
// the ratchet consumes it directly (the amendment's "commit the measured baseline JSON under docs/benchmarks").

const (
	perfSamples      = 30
	perfWarmup       = 5
	perfAllocTolFrac = 0.30 // allow 30% growth in allocated bytes before the ratchet trips
)

// perfWorkloadFiles is the pinned workload: a fixed number of files, each a mix of the labeled corpus lines,
// so the scanned bytes are stable across runs and platforms.
func writePerfWorkload(t *testing.T, dir string) {
	t.Helper()
	corpus := buildSecretsCorpus()
	var block string
	for _, c := range corpus {
		block += c.value + "\n"
	}
	// 40 files of the same content give the scanner a non-trivial, stable workload.
	for i := 0; i < 40; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%02d.txt", i)), []byte(block), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSecretScanPerfGate(t *testing.T) {
	if testing.Short() {
		t.Skip("perf gate skipped in -short")
	}
	dir := t.TempDir()
	writePerfWorkload(t, dir)
	scanner := New()
	scan := func() {
		if _, err := scanner.ScanFiles(context.Background(), dir); err != nil {
			t.Fatalf("scan: %v", err)
		}
	}

	for i := 0; i < perfWarmup; i++ {
		scan()
	}
	latencies := make([]time.Duration, 0, perfSamples)
	allocBytes := make([]uint64, 0, perfSamples)
	for i := 0; i < perfSamples; i++ {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		scan()
		latencies = append(latencies, time.Since(start))
		runtime.ReadMemStats(&after)
		allocBytes = append(allocBytes, after.TotalAlloc-before.TotalAlloc)
	}

	medAlloc := medianU64(allocBytes)
	p50 := medianDur(latencies)
	p95 := percentileDur(latencies, 95)
	env := perfEnvironmentDigest()
	t.Logf("secretscan perf: env=%s samples=%d alloc_bytes(median)=%d latency_p50=%s latency_p95=%s",
		env, perfSamples, medAlloc, p50, p95)

	base, ok := loadPerfBaseline(t)
	if !ok {
		// A missing baseline must fail, not silently disable the gate: the committed baseline is what the
		// ratchet consumes, so its absence is a broken gate, not a pass.
		t.Fatalf("no committed baseline at %s: the performance ratchet is disabled (commit the measured baseline)", perfBaselinePath)
	}
	if base.AllocBytes == 0 {
		t.Fatalf("malformed baseline %s: alloc_bytes_median is zero", perfBaselinePath)
	}
	// Allocation ratchet: deterministic per toolchain, so it gates in every CI environment (the tolerance
	// absorbs minor cross-toolchain differences).
	ceil := allocCeiling(base.AllocBytes, perfAllocTolFrac)
	if medAlloc > ceil {
		t.Errorf("secretscan allocations regressed: median %d bytes exceeds baseline %d + %.0f%% = %d",
			medAlloc, base.AllocBytes, perfAllocTolFrac*100, ceil)
	}
	// Latency is CPU-dependent; only report a comparison when the environment matches the baseline's.
	if base.EnvironmentDigest == env {
		t.Logf("latency vs same-environment baseline: p50 %s (baseline %dms), p95 %s (baseline %dms)",
			p50, base.LatencyP50Millis, p95, base.LatencyP95Millis)
	} else {
		t.Logf("latency not gated: current environment %s differs from baseline %s", env, base.EnvironmentDigest)
	}
}

// perfBaseline is the committed reference measurement.
type perfBaseline struct {
	Schema            string `json:"schema"`
	Target            string `json:"target"`
	EnvironmentDigest string `json:"environment_digest"`
	GoVersion         string `json:"go_version"`
	Samples           int    `json:"samples"`
	AllocBytes        uint64 `json:"alloc_bytes_median"`
	LatencyP50Millis  int64  `json:"latency_p50_millis"`
	LatencyP95Millis  int64  `json:"latency_p95_millis"`
}

const perfBaselinePath = "../../../../docs/benchmarks/secretscan-perf.json"

func loadPerfBaseline(t *testing.T) (perfBaseline, bool) {
	t.Helper()
	data, err := os.ReadFile(perfBaselinePath)
	if err != nil {
		return perfBaseline{}, false
	}
	var b perfBaseline
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("decode perf baseline %s: %v", perfBaselinePath, err)
	}
	return b, true
}

// perfEnvironmentDigest identifies the measurement environment without asserting cross-hardware comparability.
func perfEnvironmentDigest() string {
	seed := fmt.Sprintf("%s|%s|%s|%d", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	sum := sha256.Sum256([]byte(seed))
	return "env:" + hex.EncodeToString(sum[:8])
}

// allocCeiling is the ratchet's upper bound: the baseline allocation plus the tolerance fraction. Factored
// out so the gate's decision is unit-tested without running a scan.
func allocCeiling(baseline uint64, tolFrac float64) uint64 {
	return uint64(float64(baseline) * (1 + tolFrac))
}

// TestAllocRatchetFires proves the allocation gate actually catches a regression and passes at/under the
// ceiling, independent of a live scan, so the gate's decision cannot silently rot.
func TestAllocRatchetFires(t *testing.T) {
	const base = 1_000_000
	ceil := allocCeiling(base, 0.30) // 1,300,000
	cases := []struct {
		name    string
		median  uint64
		regress bool
	}{
		{"well under", 900_000, false},
		{"at ceiling", ceil, false}, // strict '>' so exactly at the ceiling passes
		{"just over ceiling", ceil + 1, true},
		{"gross regression", 2_000_000, true},
	}
	for _, c := range cases {
		if got := c.median > ceil; got != c.regress {
			t.Errorf("%s: median %d vs ceiling %d, regressed=%v want %v", c.name, c.median, ceil, got, c.regress)
		}
	}
}

func TestMedianU64(t *testing.T) {
	if got := medianU64([]uint64{5, 1, 3, 2, 4}); got != 3 {
		t.Errorf("median = %d, want 3", got)
	}
}

func medianU64(xs []uint64) uint64 {
	s := append([]uint64(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

func medianDur(xs []time.Duration) time.Duration { return percentileDur(xs, 50) }

func percentileDur(xs []time.Duration, p int) time.Duration {
	s := append([]time.Duration(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	idx := (p * len(s)) / 100
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}
