package ownsbom

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
	"strings"
	"testing"
	"time"
)

// perf_test.go is the owned SBOM-producer performance gate (#1040 A6, the "pinned source" target class). It
// measures repeated owned SBOM generation over a pinned synthetic source tree and ratchets on BYTES ALLOCATED
// per generation. Allocation is deterministic for a given Go toolchain and input (it does not depend on CPU
// count or clock speed), so unlike wall-clock latency it gives a stable cross-machine regression signal; the
// 30% tolerance absorbs the small differences a different Go minor version can introduce while catching a real
// regression (a leak or an added copy that inflates allocations). Wall-clock latency IS CPU-dependent, so it
// is only recorded and compared to the baseline within the same environment. The baseline lives at
// docs/benchmarks/ownsbom-perf.json and the ratchet consumes it directly, mirroring the secret-scan perf gate.

const (
	ownsbomPerfSamples      = 20
	ownsbomPerfWarmup       = 3
	ownsbomPerfAllocTolFrac = 0.30 // allow 30% growth in allocated bytes before the ratchet trips
	// ownsbomPerfNPMPackages / ownsbomPerfGoModules size the pinned workload; a fixed count keeps the scanned
	// bytes and the produced component set stable across runs and platforms.
	ownsbomPerfNPMPackages = 800
	ownsbomPerfGoModules   = 400
)

// writeOwnsbomWorkload writes a pinned synthetic source tree: one npm lockfile (v3) with a fixed number of
// packages and one go.mod with a fixed number of requires. The content is fully deterministic (no randomness),
// so the workload bytes and the generated component set are identical on every run.
func writeOwnsbomWorkload(t *testing.T, dir string) {
	t.Helper()
	var lock strings.Builder
	lock.WriteString(`{"name":"perf","lockfileVersion":3,"packages":{"":{"name":"perf"}`)
	for i := 0; i < ownsbomPerfNPMPackages; i++ {
		fmt.Fprintf(&lock, `,"node_modules/pkg%04d":{"version":"1.%d.%d","integrity":"sha512-perf%04d"}`, i, i%50, i%17, i)
	}
	lock.WriteString("}}")
	mustWrite(t, filepath.Join(dir, "package-lock.json"), lock.String())

	var gomod strings.Builder
	gomod.WriteString("module github.com/example/perf\n\ngo 1.27\n\nrequire (\n")
	for i := 0; i < ownsbomPerfGoModules; i++ {
		fmt.Fprintf(&gomod, "\tgithub.com/example/mod%04d v1.%d.%d\n", i, i%40, i%13)
	}
	gomod.WriteString(")\n")
	mustWrite(t, filepath.Join(dir, "go.mod"), gomod.String())
}

func TestOwnsbomPerfGate(t *testing.T) {
	if testing.Short() {
		t.Skip("perf gate skipped in -short")
	}
	dir := t.TempDir()
	writeOwnsbomWorkload(t, dir)
	reg, err := DefaultRegistry()
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	gen := func() int {
		doc, gerr := reg.Generate(context.Background(), dir)
		if gerr != nil {
			t.Fatalf("generate: %v", gerr)
		}
		return len(doc.Components)
	}

	var components int
	for i := 0; i < ownsbomPerfWarmup; i++ {
		components = gen()
	}
	// The workload must actually produce the pinned component set, else the gate would ratchet a no-op.
	if want := ownsbomPerfNPMPackages + ownsbomPerfGoModules; components != want {
		t.Fatalf("workload produced %d components, want %d (fixture drift would make the perf ratchet meaningless)", components, want)
	}

	latencies := make([]time.Duration, 0, ownsbomPerfSamples)
	allocBytes := make([]uint64, 0, ownsbomPerfSamples)
	for i := 0; i < ownsbomPerfSamples; i++ {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		gen()
		latencies = append(latencies, time.Since(start))
		runtime.ReadMemStats(&after)
		allocBytes = append(allocBytes, after.TotalAlloc-before.TotalAlloc)
	}

	medAlloc := ownsbomMedianU64(allocBytes)
	p50 := ownsbomPercentileDur(latencies, 50)
	p95 := ownsbomPercentileDur(latencies, 95)
	env := ownsbomPerfEnvironmentDigest()
	t.Logf("ownsbom perf: env=%s components=%d samples=%d alloc_bytes(median)=%d latency_p50=%s latency_p95=%s",
		env, components, ownsbomPerfSamples, medAlloc, p50, p95)

	base, ok := loadOwnsbomPerfBaseline(t)
	if !ok {
		// A missing baseline must fail, not silently disable the gate: the committed baseline is what the
		// ratchet consumes, so its absence is a broken gate, not a pass.
		t.Fatalf("no committed baseline at %s: the performance ratchet is disabled (commit the measured baseline)", ownsbomPerfBaselinePath)
	}
	if base.AllocBytes == 0 {
		t.Fatalf("malformed baseline %s: alloc_bytes_median is zero", ownsbomPerfBaselinePath)
	}
	ceil := ownsbomAllocCeiling(base.AllocBytes, ownsbomPerfAllocTolFrac)
	if medAlloc > ceil {
		t.Errorf("ownsbom allocations regressed: median %d bytes exceeds baseline %d + %.0f%% = %d",
			medAlloc, base.AllocBytes, ownsbomPerfAllocTolFrac*100, ceil)
	}
	if base.EnvironmentDigest == env {
		t.Logf("latency vs same-environment baseline: p50 %s (baseline %dms), p95 %s (baseline %dms)",
			p50, base.LatencyP50Millis, p95, base.LatencyP95Millis)
	} else {
		t.Logf("latency not gated: current environment %s differs from baseline %s", env, base.EnvironmentDigest)
	}
}

// ownsbomPerfBaseline is the committed reference measurement.
type ownsbomPerfBaseline struct {
	Schema            string `json:"schema"`
	Target            string `json:"target"`
	EnvironmentDigest string `json:"environment_digest"`
	GoVersion         string `json:"go_version"`
	Samples           int    `json:"samples"`
	Components        int    `json:"components"`
	AllocBytes        uint64 `json:"alloc_bytes_median"`
	LatencyP50Millis  int64  `json:"latency_p50_millis"`
	LatencyP95Millis  int64  `json:"latency_p95_millis"`
}

const ownsbomPerfBaselinePath = "../../../../docs/benchmarks/ownsbom-perf.json"

func loadOwnsbomPerfBaseline(t *testing.T) (ownsbomPerfBaseline, bool) {
	t.Helper()
	data, err := os.ReadFile(ownsbomPerfBaselinePath)
	if err != nil {
		return ownsbomPerfBaseline{}, false
	}
	var b ownsbomPerfBaseline
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("decode perf baseline %s: %v", ownsbomPerfBaselinePath, err)
	}
	return b, true
}

func ownsbomPerfEnvironmentDigest() string {
	seed := fmt.Sprintf("%s|%s|%s|%d", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	sum := sha256.Sum256([]byte(seed))
	return "env:" + hex.EncodeToString(sum[:8])
}

// ownsbomAllocCeiling is the ratchet's upper bound: the baseline allocation plus the tolerance fraction.
// Factored out so the gate's decision is unit-tested without running a generation.
func ownsbomAllocCeiling(baseline uint64, tolFrac float64) uint64 {
	return uint64(float64(baseline) * (1 + tolFrac))
}

// TestOwnsbomAllocRatchetFires proves the allocation gate actually catches a regression and passes at/under
// the ceiling, independent of a live generation, so the gate's decision cannot silently rot.
func TestOwnsbomAllocRatchetFires(t *testing.T) {
	const base = 2_000_000
	ceil := ownsbomAllocCeiling(base, 0.30) // 2,600,000
	cases := []struct {
		name    string
		median  uint64
		regress bool
	}{
		{"well under", 1_800_000, false},
		{"at ceiling", ceil, false}, // strict '>' so exactly at the ceiling passes
		{"just over ceiling", ceil + 1, true},
		{"gross regression", 4_000_000, true},
	}
	for _, c := range cases {
		if got := c.median > ceil; got != c.regress {
			t.Errorf("%s: median %d vs ceiling %d, regressed=%v want %v", c.name, c.median, ceil, got, c.regress)
		}
	}
}

func ownsbomMedianU64(xs []uint64) uint64 {
	s := append([]uint64(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

func ownsbomPercentileDur(xs []time.Duration, p int) time.Duration {
	s := append([]time.Duration(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	idx := (p * len(s)) / 100
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}

func TestOwnsbomMedianU64(t *testing.T) {
	if got := ownsbomMedianU64([]uint64{5, 1, 3, 2, 4}); got != 3 {
		t.Errorf("median = %d, want 3", got)
	}
}
