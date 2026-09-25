package acquire

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchperf"
)

// imagerootfs_perf_test.go is the owned image-extraction performance gate (#1040 A6). It measures repeated
// extractions of a pinned, in-repo OCI layout fixture and ratchets on BYTES ALLOCATED per extraction (via the
// shared benchperf contract). extractOCIRootFS reads a LOCAL OCI layout (no network, no registry), so the
// workload is fully deterministic: the same layers, in the same order, with the same whiteouts and overwrites,
// produce the same assembled tree every run. Allocation is deterministic for a given Go toolchain and input, so
// it gives a stable cross-machine regression signal; the 30% tolerance absorbs the small differences a Go minor
// version can introduce while catching a real regression. Wall-clock latency is CPU-dependent, so it is only
// recorded and compared within the same environment. A committed dataset digest (a content hash of the squashed
// tree) is asserted every run, so a regression can never be masked by the fixture silently drifting.

const (
	imgPerfSamples      = 20
	imgPerfWarmup       = 3
	imgPerfAllocTolFrac = 0.30 // allow 30% growth in allocated bytes before the ratchet trips
)

const (
	imgPerfBaselinePath      = "../../../docs/benchmarks/image-extract-perf.json"
	imgPerfLargeBaselinePath = "../../../docs/benchmarks/image-extract-large-perf.json"
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

// digestExtractedTree hashes the squashed rootfs into a stable content digest: the sorted (relative-path,
// content-hash) of every regular file. It is the strongest fixture-drift guard, catching a changed file's
// bytes, a moved path, or an added/removed file, not only a changed count.
func digestExtractedTree(t *testing.T, root string) string {
	t.Helper()
	type entry struct{ rel, hash string }
	var entries []entry
	if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		content, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		sum := sha256.Sum256(content)
		entries = append(entries, entry{filepath.ToSlash(rel), fmt.Sprintf("%x", sum)})
		return nil
	}); err != nil {
		t.Fatalf("digest tree %s: %v", root, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	parts := make([]string, 0, len(entries)*2)
	for _, e := range entries {
		parts = append(parts, e.rel, e.hash)
	}
	return benchperf.DatasetDigest(parts...)
}

func TestImageExtractPerfGate(t *testing.T) {
	if testing.Short() {
		t.Skip("perf gate skipped in -short")
	}
	layout := t.TempDir()
	expected := buildImageExtractWorkload(t, layout)

	// Correctness pre-check: the fixture must assemble to exactly the squashed tree the gate measures, so a
	// perf regression is never masked by the fixture drifting. This also proves the overwrite and whiteout ran.
	dest := filepath.Join(t.TempDir(), "rootfs")
	if _, err := extractOCIRootFS(context.Background(), layout, dest, MaxWorkspaceBytes); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if got := countRegularFiles(t, dest); got != expected {
		t.Fatalf("fixture drift: extracted %d regular files, want %d", got, expected)
	}
	mustNotExist(t, filepath.Join(dest, "usr/share/doc/f0149.txt"))                      // whiteout applied
	mustContain(t, filepath.Join(dest, "usr/share/doc/f0000.txt"), docBody("doc-v2", 0)) // layer-1 overwrite won

	measureImageExtractGate(t, "small-image", layout, expected, digestExtractedTree(t, dest), imgPerfBaselinePath)
}

// TestImageExtractLargeImagePerfGate is the large-image target class. It extracts a ~5000-file, 8-layer fixture,
// so a regression that only appears at scale (a superlinear layer-application or per-file map cost that the
// 272-file small-image fixture cannot surface) is caught. The gate is identical; only the workload is larger.
func TestImageExtractLargeImagePerfGate(t *testing.T) {
	if testing.Short() {
		t.Skip("perf gate skipped in -short")
	}
	layout := t.TempDir()
	expected := buildLargeImageWorkload(t, layout)

	dest := filepath.Join(t.TempDir(), "rootfs")
	if _, err := extractOCIRootFS(context.Background(), layout, dest, MaxWorkspaceBytes); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if got := countRegularFiles(t, dest); got != expected {
		t.Fatalf("fixture drift: extracted %d regular files, want %d", got, expected)
	}
	mustNotExist(t, filepath.Join(dest, "usr/share/doc/d0990.txt"))                      // final-layer whiteout applied
	mustNotExist(t, filepath.Join(dest, "usr/share/doc/d0999.txt"))                      // final-layer whiteout applied
	mustContain(t, filepath.Join(dest, "usr/share/doc/d0000.txt"), docBody("doc-v2", 0)) // last overlay's overwrite won (correct bytes, not only count)

	measureImageExtractGate(t, "large-image", layout, expected, digestExtractedTree(t, dest), imgPerfLargeBaselinePath)
}

// measureImageExtractGate warms up, samples imgPerfSamples extractions of the layout, ratchets the median
// allocated bytes against the committed baseline, and asserts the dataset digest matches. It is shared by the
// small- and large-image gates so both classes measure and ratchet identically.
func measureImageExtractGate(t *testing.T, label, layout string, expected int, datasetDigest, baselinePath string) {
	t.Helper()
	res := benchperf.Measure(imgPerfWarmup, imgPerfSamples, func() {
		dest := filepath.Join(t.TempDir(), "rootfs")
		if _, err := extractOCIRootFS(context.Background(), layout, dest, MaxWorkspaceBytes); err != nil {
			t.Fatalf("extract: %v", err)
		}
	})
	if err := benchperf.CheckPeakEvidence(res); err != nil {
		t.Fatal(err)
	}
	env := benchperf.EnvironmentDigest()
	t.Logf("image-extract perf [%s]: release=%s env=%s samples=%d files=%d alloc_bytes(median)=%d peak_mem=%d latency_p50=%s latency_p95=%s dataset=%s throughput_ops_per_second=%.6f",
		label, benchperf.ReleaseDigest(), env, imgPerfSamples, expected, res.MedianAllocBytes, res.PeakMemoryBytes, res.LatencyP50, res.LatencyP95, datasetDigest, res.ThroughputOpsPerSecond)

	base, found, err := benchperf.Load(baselinePath, imgPerfWarmup, imgPerfSamples)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		// A missing baseline must fail, not silently disable the gate: the committed baseline is what the
		// ratchet consumes, so its absence is a broken gate, not a pass.
		t.Fatalf("no committed baseline at %s: the performance ratchet is disabled (commit the measured baseline)", baselinePath)
	}
	if datasetDigest != base.DatasetDigest {
		t.Fatalf("fixture drift [%s]: extracted-tree digest %s != committed %s (the measured workload changed)", label, datasetDigest, base.DatasetDigest)
	}
	ceil := benchperf.AllocCeiling(base.AllocBytes, imgPerfAllocTolFrac)
	if res.MedianAllocBytes > ceil {
		t.Errorf("image-extract [%s] allocations regressed: median %d bytes exceeds baseline %d + %.0f%% = %d",
			label, res.MedianAllocBytes, base.AllocBytes, imgPerfAllocTolFrac*100, ceil)
	}
	if base.EnvironmentDigest == env {
		t.Logf("latency vs same-environment baseline: p50 %s (baseline %dms), p95 %s (baseline %dms)",
			res.LatencyP50, base.LatencyP50Millis, res.LatencyP95, base.LatencyP95Millis)
	} else {
		t.Logf("latency not gated: current environment %s differs from baseline %s", env, base.EnvironmentDigest)
	}
}

// buildLargeImageWorkload assembles the large-image fixture: a 1003-file base plus six library overlays and a
// final binary+whiteout layer, exercising the layer-application, overwrite, and whiteout paths at ~5000-file
// scale across 8 layers. Content is deterministic so the allocated bytes are stable across runs and platforms.
func buildLargeImageWorkload(t *testing.T, layoutDir string) (expectedFiles int) {
	t.Helper()
	digests := make([]string, 0, 8)

	// Layer 0: base rootfs. 3 fixed OS files + 1000 docs (d0000..d0999).
	base := []layerEntry{
		dir("etc/"), reg("etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n"),
		reg("etc/hostname", "synapse-fixture\n"),
		dir("var/"), dir("var/lib/"), dir("var/lib/dpkg/"), reg("var/lib/dpkg/status", dpkgStatusFixture(400)),
		dir("usr/"), dir("usr/share/"), dir("usr/share/doc/"),
	}
	for i := 0; i < 1000; i++ {
		base = append(base, reg(fmt.Sprintf("usr/share/doc/d%04d.txt", i), docBody("doc", i)))
	}
	digests = append(digests, addLayer(t, layoutDir, true, base))

	// Layers 1..6: each adds 600 unique library files in its own directory, plus overwrites 20 base docs (same
	// path, no count change). 6 * 600 = 3600 new files.
	for layer := 1; layer <= 6; layer++ {
		entries := []layerEntry{dir(fmt.Sprintf("usr/lib/L%d/", layer))}
		for i := 0; i < 600; i++ {
			entries = append(entries, reg(fmt.Sprintf("usr/lib/L%d/f%04d.so", layer, i), docBody("lib", layer*1000+i)))
		}
		for i := 0; i < 20; i++ {
			entries = append(entries, reg(fmt.Sprintf("usr/share/doc/d%04d.txt", i), docBody("doc-v2", i)))
		}
		digests = append(digests, addLayer(t, layoutDir, true, entries))
	}

	// Layer 7: 400 binaries, plus 10 whiteouts deleting d0990..d0999 (net -10).
	top := []layerEntry{dir("usr/bin/")}
	for i := 0; i < 400; i++ {
		top = append(top, reg(fmt.Sprintf("usr/bin/b%04d", i), docBody("bin", i)))
	}
	for i := 990; i < 1000; i++ {
		top = append(top, reg(fmt.Sprintf("usr/share/doc/.wh.d%04d.txt", i), ""))
	}
	digests = append(digests, addLayer(t, layoutDir, true, top))

	finishLayout(t, layoutDir, digests)

	// 3 OS files + 1000 docs + 3600 libs + 400 bins - 10 whiteouts = 4993.
	return 3 + 1000 + 3600 + 400 - 10
}
