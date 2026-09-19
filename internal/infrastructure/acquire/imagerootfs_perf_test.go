package acquire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"
)

// imagerootfs_perf_test.go is the owned image-extraction performance gate (#1040 A6). It measures repeated
// extractions of a pinned, in-repo OCI layout fixture and ratchets on BYTES ALLOCATED per extraction.
// extractOCIRootFS reads a LOCAL OCI layout (no network, no registry), so the workload is fully deterministic:
// the same layers, in the same order, with the same whiteouts and overwrites, produce the same assembled tree
// every run. Allocation is deterministic for a given Go toolchain and input (it does not depend on CPU count
// or clock speed), so it gives a stable cross-machine regression signal; the 30% tolerance absorbs the small
// differences a Go minor version can introduce while catching a real regression (a leak, or an added copy in
// the layer-application path that inflates allocations). Wall-clock latency IS CPU-dependent, so it is only
// recorded and compared to the baseline within the same environment. The baseline lives at
// docs/benchmarks/image-extract-perf.json and the ratchet consumes it directly.

const (
	imgPerfSamples      = 20
	imgPerfWarmup       = 3
	imgPerfAllocTolFrac = 0.30 // allow 30% growth in allocated bytes before the ratchet trips
)

// buildImageExtractWorkload assembles a pinned multi-layer OCI layout fixture into layoutDir and returns the
// number of regular files the squashed tree should contain. The workload mirrors a small OS image: a base
// layer with the OS-package artifacts producers read (os-release, dpkg status) plus a documentation tree, then
// two overlay layers that add files, overwrite a few, and delete one via a whiteout, so extraction exercises
// the layering, replace, and whiteout paths, not just a flat unpack. Content is generated deterministically so
// the allocated bytes are stable across runs and platforms.
func buildImageExtractWorkload(t *testing.T, layoutDir string) (expectedFiles int) {
	t.Helper()
	// Layer 0: the base rootfs. 3 fixed OS-package artifacts + 150 documentation files.
	base := []layerEntry{
		dir("etc/"), reg("etc/os-release", "ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12\"\n"),
		reg("etc/hostname", "synapse-fixture\n"),
		dir("var/"), dir("var/lib/"), dir("var/lib/dpkg/"), reg("var/lib/dpkg/status", dpkgStatusFixture(60)),
		dir("usr/"), dir("usr/share/"), dir("usr/share/doc/"),
	}
	for i := 0; i < 150; i++ {
		base = append(base, reg(fmt.Sprintf("usr/share/doc/f%04d.txt", i), docBody("doc", i)))
	}
	l0 := addLayer(t, layoutDir, true, base)

	// Layer 1: 80 new library files, plus overwrites of 10 base documentation files (same path, new content ->
	// last-writer-wins, no net file-count change).
	over := []layerEntry{dir("usr/lib/")}
	for i := 0; i < 80; i++ {
		over = append(over, reg(fmt.Sprintf("usr/lib/l%04d.so", i), docBody("lib", i)))
	}
	for i := 0; i < 10; i++ {
		over = append(over, reg(fmt.Sprintf("usr/share/doc/f%04d.txt", i), docBody("doc-v2", i)))
	}
	l1 := addLayer(t, layoutDir, true, over)

	// Layer 2: 40 new binaries, plus a whiteout that deletes one base documentation file (net -1).
	top := []layerEntry{dir("usr/bin/")}
	for i := 0; i < 40; i++ {
		top = append(top, reg(fmt.Sprintf("usr/bin/b%04d", i), docBody("bin", i)))
	}
	top = append(top, reg("usr/share/doc/.wh.f0149.txt", "")) // whiteout deletes usr/share/doc/f0149.txt
	l2 := addLayer(t, layoutDir, true, top)

	finishLayout(t, layoutDir, []string{l0, l1, l2})

	// Squashed file count: 3 base OS files + 150 docs + 80 libs + 40 bins - 1 whiteout = 272. Overwrites keep
	// the same path, so they do not change the count.
	return 3 + 150 + 80 + 40 - 1
}

func dpkgStatusFixture(pkgs int) string {
	var b []byte
	for i := 0; i < pkgs; i++ {
		b = append(b, []byte(fmt.Sprintf("Package: pkg%04d\nStatus: install ok installed\nVersion: 1.%d.0\nArchitecture: amd64\n\n", i, i))...)
	}
	return string(b)
}

// docBody generates deterministic, non-trivial file content keyed by (kind, index).
func docBody(kind string, i int) string {
	var b []byte
	for line := 0; line < 8; line++ {
		b = append(b, []byte(fmt.Sprintf("%s entry %04d line %d: the quick brown fox jumps over the lazy dog\n", kind, i, line))...)
	}
	return string(b)
}

func countRegularFiles(t *testing.T, root string) int {
	t.Helper()
	n := 0
	if err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			n++
		}
		return nil
	}); err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return n
}

func TestImageExtractPerfGate(t *testing.T) {
	if testing.Short() {
		t.Skip("perf gate skipped in -short")
	}
	layout := t.TempDir()
	expected := buildImageExtractWorkload(t, layout)

	extractOnce := func() string {
		dest := filepath.Join(t.TempDir(), "rootfs")
		if _, err := extractOCIRootFS(context.Background(), layout, dest, MaxWorkspaceBytes); err != nil {
			t.Fatalf("extract: %v", err)
		}
		return dest
	}

	// Correctness pre-check: the fixture must assemble to exactly the squashed tree the gate measures, so a
	// perf regression is never masked by the fixture drifting to a smaller/larger workload. This also proves
	// the overwrite and whiteout paths ran.
	dest := extractOnce()
	if got := countRegularFiles(t, dest); got != expected {
		t.Fatalf("fixture drift: extracted %d regular files, want %d", got, expected)
	}
	mustNotExist(t, filepath.Join(dest, "usr/share/doc/f0149.txt"))                      // whiteout applied
	mustContain(t, filepath.Join(dest, "usr/share/doc/f0000.txt"), docBody("doc-v2", 0)) // layer-1 overwrite won

	for i := 0; i < imgPerfWarmup; i++ {
		extractOnce()
	}
	latencies := make([]time.Duration, 0, imgPerfSamples)
	allocBytes := make([]uint64, 0, imgPerfSamples)
	for i := 0; i < imgPerfSamples; i++ {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		extractOnce()
		latencies = append(latencies, time.Since(start))
		runtime.ReadMemStats(&after)
		allocBytes = append(allocBytes, after.TotalAlloc-before.TotalAlloc)
	}

	medAlloc := imgMedianU64(allocBytes)
	p50 := imgPercentileDur(latencies, 50)
	p95 := imgPercentileDur(latencies, 95)
	env := imgPerfEnvironmentDigest()
	t.Logf("image-extract perf: env=%s samples=%d files=%d alloc_bytes(median)=%d latency_p50=%s latency_p95=%s",
		env, imgPerfSamples, expected, medAlloc, p50, p95)

	base, ok := loadImgPerfBaseline(t)
	if !ok {
		// A missing baseline must fail, not silently disable the gate: the committed baseline is what the
		// ratchet consumes, so its absence is a broken gate, not a pass.
		t.Fatalf("no committed baseline at %s: the performance ratchet is disabled (commit the measured baseline)", imgPerfBaselinePath)
	}
	if base.AllocBytes == 0 {
		t.Fatalf("malformed baseline %s: alloc_bytes_median is zero", imgPerfBaselinePath)
	}
	ceil := imgAllocCeiling(base.AllocBytes, imgPerfAllocTolFrac)
	if medAlloc > ceil {
		t.Errorf("image-extract allocations regressed: median %d bytes exceeds baseline %d + %.0f%% = %d",
			medAlloc, base.AllocBytes, imgPerfAllocTolFrac*100, ceil)
	}
	if base.EnvironmentDigest == env {
		t.Logf("latency vs same-environment baseline: p50 %s (baseline %dms), p95 %s (baseline %dms)",
			p50, base.LatencyP50Millis, p95, base.LatencyP95Millis)
	} else {
		t.Logf("latency not gated: current environment %s differs from baseline %s", env, base.EnvironmentDigest)
	}
}

// imgPerfBaseline is the committed reference measurement for image extraction.
type imgPerfBaseline struct {
	Schema            string `json:"schema"`
	Target            string `json:"target"`
	EnvironmentDigest string `json:"environment_digest"`
	GoVersion         string `json:"go_version"`
	Samples           int    `json:"samples"`
	AllocBytes        uint64 `json:"alloc_bytes_median"`
	LatencyP50Millis  int64  `json:"latency_p50_millis"`
	LatencyP95Millis  int64  `json:"latency_p95_millis"`
}

const (
	imgPerfBaselinePath   = "../../../docs/benchmarks/image-extract-perf.json"
	imgPerfBaselineSchema = "synapse-scan-perf-v1"
)

// loadImgPerfBaseline reads the committed baseline. It fails closed on a wrong schema or a sample count that
// does not match this gate's imgPerfSamples: a baseline measured under a different schema or a different sample
// count is not comparable, so silently ratcheting against it would be a stale, meaningless gate rather than a
// hard failure. A missing file returns (_, false) so the caller reports the disabled-gate error.
func loadImgPerfBaseline(t *testing.T) (imgPerfBaseline, bool) {
	t.Helper()
	data, err := os.ReadFile(imgPerfBaselinePath)
	if err != nil {
		return imgPerfBaseline{}, false
	}
	var b imgPerfBaseline
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatalf("decode perf baseline %s: %v", imgPerfBaselinePath, err)
	}
	if b.Schema != imgPerfBaselineSchema {
		t.Fatalf("perf baseline %s has schema %q, want %q (baseline is not comparable)", imgPerfBaselinePath, b.Schema, imgPerfBaselineSchema)
	}
	if b.Samples != imgPerfSamples {
		t.Fatalf("perf baseline %s was measured with %d samples, gate uses %d (re-baseline)", imgPerfBaselinePath, b.Samples, imgPerfSamples)
	}
	return b, true
}

func imgPerfEnvironmentDigest() string {
	seed := fmt.Sprintf("%s|%s|%s|%d", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	sum := sha256.Sum256([]byte(seed))
	return "env:" + hex.EncodeToString(sum[:8])
}

// imgAllocCeiling is the ratchet's upper bound: the baseline allocation plus the tolerance fraction. Factored
// out so the gate's decision is unit-tested without running an extraction.
func imgAllocCeiling(baseline uint64, tolFrac float64) uint64 {
	return uint64(float64(baseline) * (1 + tolFrac))
}

// TestImageExtractAllocRatchetFires proves the allocation gate catches a regression and passes at/under the
// ceiling, independent of a live extraction, so the gate's decision cannot silently rot.
func TestImageExtractAllocRatchetFires(t *testing.T) {
	const base = 1_000_000
	ceil := imgAllocCeiling(base, 0.30) // 1,300,000
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

func imgMedianU64(xs []uint64) uint64 {
	s := append([]uint64(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

func imgPercentileDur(xs []time.Duration, p int) time.Duration {
	s := append([]time.Duration(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	idx := (p * len(s)) / 100
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}
