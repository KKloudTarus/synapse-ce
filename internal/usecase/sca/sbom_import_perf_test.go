package sca

import (
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

// sbom_import_perf_test.go is the owned SBOM-INGEST performance gate (#1040 A6, the "pinned SBOM" target
// class). It measures repeated parsing of a pinned client-supplied CycloneDX SBOM into the owned component
// model and ratchets on BYTES ALLOCATED per parse. Allocation is deterministic for a given Go toolchain and
// input, so unlike wall-clock latency it gives a stable cross-machine regression signal; the 30% tolerance
// absorbs the small differences a different Go minor version can introduce while catching a real regression.
// Wall-clock latency is recorded and compared only within the same environment digest. The baseline lives at
// docs/benchmarks/cyclonedx-import-perf.json, mirroring the secret-scan and ownsbom-producer perf gates.

const (
	cdxImportPerfSamples      = 20
	cdxImportPerfWarmup       = 3
	cdxImportPerfAllocTolFrac = 0.30
	// cdxImportPerfComponents sizes the pinned SBOM; a fixed count keeps the parsed component set stable.
	cdxImportPerfComponents = 1500
)

// writeCDXWorkload returns a pinned CycloneDX 1.5 SBOM with a fixed number of components, each carrying a
// name/version/purl (so it resolves to an owned component). The content is fully deterministic.
func buildCDXWorkload() []byte {
	var b strings.Builder
	b.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"name":"perf-app"}},"components":[`)
	for i := 0; i < cdxImportPerfComponents; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"type":"library","name":"pkg%04d","version":"1.%d.%d","purl":"pkg:npm/pkg%04d@1.%d.%d","licenses":[{"license":{"id":"MIT"}}]}`,
			i, i%50, i%17, i, i%50, i%17)
	}
	b.WriteString(`]}`)
	return []byte(b.String())
}

func TestSBOMImportPerfGate(t *testing.T) {
	if testing.Short() {
		t.Skip("perf gate skipped in -short")
	}
	data := buildCDXWorkload()
	parse := func() int {
		comps, err := ParseCycloneDXComponents(data)
		if err != nil {
			t.Fatalf("parse cyclonedx: %v", err)
		}
		return len(comps)
	}

	var components int
	for i := 0; i < cdxImportPerfWarmup; i++ {
		components = parse()
	}
	if components != cdxImportPerfComponents {
		t.Fatalf("workload parsed %d components, want %d (fixture drift would make the perf ratchet meaningless)", components, cdxImportPerfComponents)
	}

	latencies := make([]time.Duration, 0, cdxImportPerfSamples)
	allocBytes := make([]uint64, 0, cdxImportPerfSamples)
	for i := 0; i < cdxImportPerfSamples; i++ {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		parse()
		latencies = append(latencies, time.Since(start))
		runtime.ReadMemStats(&after)
		allocBytes = append(allocBytes, after.TotalAlloc-before.TotalAlloc)
	}

	medAlloc := cdxImportMedianU64(allocBytes)
	p50 := cdxImportPercentileDur(latencies, 50)
	p95 := cdxImportPercentileDur(latencies, 95)
	env := cdxImportPerfEnvironmentDigest()
	t.Logf("cyclonedx-import perf: env=%s components=%d samples=%d alloc_bytes(median)=%d latency_p50=%s latency_p95=%s",
		env, components, cdxImportPerfSamples, medAlloc, p50, p95)

	base, ok := loadCDXImportPerfBaseline(t)
	if !ok {
		t.Fatalf("no committed baseline at %s: the performance ratchet is disabled (commit the measured baseline)", cdxImportPerfBaselinePath)
	}
	if base.AllocBytes == 0 {
		t.Fatalf("malformed baseline %s: alloc_bytes_median is zero", cdxImportPerfBaselinePath)
	}
	ceil := cdxImportAllocCeiling(base.AllocBytes, cdxImportPerfAllocTolFrac)
	if medAlloc > ceil {
		t.Errorf("cyclonedx-import allocations regressed: median %d bytes exceeds baseline %d + %.0f%% = %d",
			medAlloc, base.AllocBytes, cdxImportPerfAllocTolFrac*100, ceil)
	}
	if base.EnvironmentDigest == env {
		t.Logf("latency vs same-environment baseline: p50 %s (baseline %dms), p95 %s (baseline %dms)",
			p50, base.LatencyP50Millis, p95, base.LatencyP95Millis)
	} else {
		t.Logf("latency not gated: current environment %s differs from baseline %s", env, base.EnvironmentDigest)
	}
}

type cdxImportPerfBaseline struct {
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

const cdxImportPerfBaselinePath = "../../../docs/benchmarks/cyclonedx-import-perf.json"

func loadCDXImportPerfBaseline(t *testing.T) (cdxImportPerfBaseline, bool) {
	t.Helper()
	data, err := os.ReadFile(cdxImportPerfBaselinePath)
	if err != nil {
		return cdxImportPerfBaseline{}, false
	}
	var b cdxImportPerfBaseline
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("decode perf baseline %s: %v", cdxImportPerfBaselinePath, err)
	}
	return b, true
}

func cdxImportPerfEnvironmentDigest() string {
	seed := fmt.Sprintf("%s|%s|%s|%d", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	sum := sha256.Sum256([]byte(seed))
	return "env:" + hex.EncodeToString(sum[:8])
}

// cdxImportAllocCeiling is the ratchet's upper bound: baseline allocation plus the tolerance fraction.
func cdxImportAllocCeiling(baseline uint64, tolFrac float64) uint64 {
	return uint64(float64(baseline) * (1 + tolFrac))
}

// TestCDXImportAllocRatchetFires proves the allocation gate catches a regression and passes at/under the
// ceiling without a live parse, so the gate's decision cannot silently rot.
func TestCDXImportAllocRatchetFires(t *testing.T) {
	const base = 3_000_000
	ceil := cdxImportAllocCeiling(base, 0.30) // 3,900,000
	cases := []struct {
		name    string
		median  uint64
		regress bool
	}{
		{"well under", 2_700_000, false},
		{"at ceiling", ceil, false},
		{"just over ceiling", ceil + 1, true},
		{"gross regression", 6_000_000, true},
	}
	for _, c := range cases {
		if got := c.median > ceil; got != c.regress {
			t.Errorf("%s: median %d vs ceiling %d, regressed=%v want %v", c.name, c.median, ceil, got, c.regress)
		}
	}
}

func cdxImportMedianU64(xs []uint64) uint64 {
	s := append([]uint64(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

func cdxImportPercentileDur(xs []time.Duration, p int) time.Duration {
	s := append([]time.Duration(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	idx := (p * len(s)) / 100
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}

func TestCDXImportMedianU64(t *testing.T) {
	if got := cdxImportMedianU64([]uint64{5, 1, 3, 2, 4}); got != 3 {
		t.Errorf("median = %d, want 3", got)
	}
}
