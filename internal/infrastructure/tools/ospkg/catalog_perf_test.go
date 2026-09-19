package ospkg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// catalog_perf_test.go is the owned OS-package-cataloging performance gate (#1040 A6). OS-package cataloging
// is the dominant per-image detection cost after rootfs assembly, so it is measured as its own target class:
// repeated cataloging of a pinned fixture rootfs (a large dpkg status DB), ratcheting on BYTES ALLOCATED per
// catalog. Allocation is deterministic for a given Go toolchain and input, so unlike wall-clock latency it
// gives a stable cross-machine regression signal; the 30% tolerance absorbs the small differences a different
// Go minor version can introduce. Wall-clock latency is recorded and compared only within the same environment
// digest. It measures cataloging in isolation (a fixture rootfs), not OCI layer extraction, which is
// environment-specific and belongs in the trusted CI-workflow lane. The baseline lives at
// docs/benchmarks/ospkg-catalog-perf.json, mirroring the other owned perf gates.

const (
	catalogPerfSamples      = 20
	catalogPerfWarmup       = 3
	catalogPerfAllocTolFrac = 0.30
	// catalogPerfDebPackages sizes the pinned workload; a fixed count keeps the scanned bytes and the cataloged
	// component set stable across runs and platforms.
	catalogPerfDebPackages = 1500
)

// buildCatalogWorkload writes a pinned fixture rootfs: a Debian os-release plus a dpkg status DB with a fixed
// number of installed packages. The content is fully deterministic, so the workload bytes and the cataloged
// component set are identical on every run.
func buildCatalogWorkload(t *testing.T) string {
	t.Helper()
	var status strings.Builder
	for i := 0; i < catalogPerfDebPackages; i++ {
		fmt.Fprintf(&status, "Package: pkg%04d\nStatus: install ok installed\nVersion: 1.%d.%d-%ddeb12u1\nArchitecture: amd64\nSource: src%04d\n\n",
			i, i%50, i%17, i%9, i)
	}
	return writeRootfs(t, map[string]string{
		"etc/os-release":      "ID=debian\nVERSION_ID=\"12\"\n",
		"var/lib/dpkg/status": status.String(),
	})
}

func TestOSPkgCatalogPerfGate(t *testing.T) {
	if testing.Short() {
		t.Skip("perf gate skipped in -short")
	}
	rootfs := buildCatalogWorkload(t)
	cat := New()
	catalog := func() int {
		res, err := cat.Catalog(context.Background(), rootfs)
		if err != nil {
			t.Fatalf("catalog: %v", err)
		}
		return len(res.Components)
	}

	var components int
	for i := 0; i < catalogPerfWarmup; i++ {
		components = catalog()
	}
	if components != catalogPerfDebPackages {
		t.Fatalf("workload cataloged %d components, want %d (fixture drift would make the perf ratchet meaningless)", components, catalogPerfDebPackages)
	}

	latencies := make([]time.Duration, 0, catalogPerfSamples)
	allocBytes := make([]uint64, 0, catalogPerfSamples)
	for i := 0; i < catalogPerfSamples; i++ {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		catalog()
		latencies = append(latencies, time.Since(start))
		runtime.ReadMemStats(&after)
		allocBytes = append(allocBytes, after.TotalAlloc-before.TotalAlloc)
	}

	medAlloc := catalogMedianU64(allocBytes)
	p50 := catalogPercentileDur(latencies, 50)
	p95 := catalogPercentileDur(latencies, 95)
	env := catalogPerfEnvironmentDigest()
	t.Logf("ospkg-catalog perf: env=%s components=%d samples=%d alloc_bytes(median)=%d latency_p50=%s latency_p95=%s",
		env, components, catalogPerfSamples, medAlloc, p50, p95)

	base, ok := loadCatalogPerfBaseline(t)
	if !ok {
		t.Fatalf("no committed baseline at %s: the performance ratchet is disabled (commit the measured baseline)", catalogPerfBaselinePath)
	}
	if base.AllocBytes == 0 {
		t.Fatalf("malformed baseline %s: alloc_bytes_median is zero", catalogPerfBaselinePath)
	}
	ceil := catalogAllocCeiling(base.AllocBytes, catalogPerfAllocTolFrac)
	if medAlloc > ceil {
		t.Errorf("ospkg-catalog allocations regressed: median %d bytes exceeds baseline %d + %.0f%% = %d",
			medAlloc, base.AllocBytes, catalogPerfAllocTolFrac*100, ceil)
	}
	if base.EnvironmentDigest == env {
		t.Logf("latency vs same-environment baseline: p50 %s (baseline %dms), p95 %s (baseline %dms)",
			p50, base.LatencyP50Millis, p95, base.LatencyP95Millis)
	} else {
		t.Logf("latency not gated: current environment %s differs from baseline %s", env, base.EnvironmentDigest)
	}
}

type catalogPerfBaseline struct {
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

const catalogPerfBaselinePath = "../../../../docs/benchmarks/ospkg-catalog-perf.json"

func loadCatalogPerfBaseline(t *testing.T) (catalogPerfBaseline, bool) {
	t.Helper()
	data, err := os.ReadFile(catalogPerfBaselinePath)
	if err != nil {
		return catalogPerfBaseline{}, false
	}
	var b catalogPerfBaseline
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("decode perf baseline %s: %v", catalogPerfBaselinePath, err)
	}
	return b, true
}

func catalogPerfEnvironmentDigest() string {
	seed := fmt.Sprintf("%s|%s|%s|%d", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	sum := sha256.Sum256([]byte(seed))
	return "env:" + hex.EncodeToString(sum[:8])
}

// catalogAllocCeiling is the ratchet's upper bound: baseline allocation plus the tolerance fraction.
func catalogAllocCeiling(baseline uint64, tolFrac float64) uint64 {
	return uint64(float64(baseline) * (1 + tolFrac))
}

// TestCatalogAllocRatchetFires proves the allocation gate catches a regression and passes at/under the ceiling
// without a live catalog, so the gate's decision cannot silently rot.
func TestCatalogAllocRatchetFires(t *testing.T) {
	const base = 5_000_000
	ceil := catalogAllocCeiling(base, 0.30) // 6,500,000
	cases := []struct {
		name    string
		median  uint64
		regress bool
	}{
		{"well under", 4_500_000, false},
		{"at ceiling", ceil, false},
		{"just over ceiling", ceil + 1, true},
		{"gross regression", 10_000_000, true},
	}
	for _, c := range cases {
		if got := c.median > ceil; got != c.regress {
			t.Errorf("%s: median %d vs ceiling %d, regressed=%v want %v", c.name, c.median, ceil, got, c.regress)
		}
	}
}

func catalogMedianU64(xs []uint64) uint64 {
	s := append([]uint64(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

func catalogPercentileDur(xs []time.Duration, p int) time.Duration {
	s := append([]time.Duration(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	idx := (p * len(s)) / 100
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}

func TestCatalogMedianU64(t *testing.T) {
	if got := catalogMedianU64([]uint64{5, 1, 3, 2, 4}); got != 3 {
		t.Errorf("median = %d, want 3", got)
	}
}
