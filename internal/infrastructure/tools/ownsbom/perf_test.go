package ownsbom

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchperf"
)

// perf_test.go is the owned SBOM-producer performance gate (#1040 A6, the "pinned source" target class). It
// measures repeated owned SBOM generation over a pinned synthetic source tree and ratchets on BYTES ALLOCATED
// per generation via the shared benchperf contract. Allocation is deterministic for a given Go toolchain and
// input, so unlike wall-clock latency it gives a stable cross-machine regression signal; the 30% tolerance
// absorbs the small differences a different Go minor version can introduce while catching a real regression.
// Wall-clock latency IS CPU-dependent, so it is only recorded and compared within the same environment. The
// baseline lives at docs/benchmarks/ownsbom-perf.json.

const (
	ownsbomPerfSamples      = 20
	ownsbomPerfWarmup       = 3
	ownsbomPerfAllocTolFrac = 0.30 // allow 30% growth in allocated bytes before the ratchet trips
	// ownsbomPerfNPMPackages / ownsbomPerfGoModules size the pinned workload; a fixed count keeps the scanned
	// bytes and the produced component set stable across runs and platforms.
	ownsbomPerfNPMPackages  = 800
	ownsbomPerfGoModules    = 400
	ownsbomPerfBaselinePath = "../../../../docs/benchmarks/ownsbom-perf.json"
)

// writeOwnsbomWorkload writes a pinned synthetic source tree: one npm lockfile (v3) with a fixed number of
// packages and one go.mod with a fixed number of requires. The content is fully deterministic (no randomness),
// so the workload bytes and the generated component set are identical on every run. It returns the dataset
// digest of the fixture content so the gate can assert its live workload matches the committed baseline.
func writeOwnsbomWorkload(t *testing.T, dir string) (datasetDigest string) {
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

	return benchperf.DatasetDigest("package-lock.json", lock.String(), "go.mod", gomod.String())
}

func TestOwnsbomPerfGate(t *testing.T) {
	if testing.Short() {
		t.Skip("perf gate skipped in -short")
	}
	dir := t.TempDir()
	datasetDigest := writeOwnsbomWorkload(t, dir)
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

	// The workload must actually produce the pinned component set, else the gate would ratchet a no-op.
	if want := ownsbomPerfNPMPackages + ownsbomPerfGoModules; gen() != want {
		t.Fatalf("workload produced a different component count than %d (fixture drift would make the perf ratchet meaningless)", want)
	}

	res := benchperf.Measure(ownsbomPerfWarmup, ownsbomPerfSamples, func() { gen() })
	env := benchperf.EnvironmentDigest()
	t.Logf("ownsbom perf: env=%s components=%d samples=%d alloc_bytes(median)=%d peak_mem=%d latency_p50=%s latency_p95=%s dataset=%s",
		env, ownsbomPerfNPMPackages+ownsbomPerfGoModules, ownsbomPerfSamples, res.MedianAllocBytes, res.PeakMemoryBytes, res.LatencyP50, res.LatencyP95, datasetDigest)

	base, found, err := benchperf.Load(ownsbomPerfBaselinePath, ownsbomPerfSamples)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("no committed baseline at %s: the performance ratchet is disabled (commit the measured baseline)", ownsbomPerfBaselinePath)
	}
	if datasetDigest != base.DatasetDigest {
		t.Fatalf("fixture drift: workload digest %s != committed %s (the measured workload changed)", datasetDigest, base.DatasetDigest)
	}
	ceil := benchperf.AllocCeiling(base.AllocBytes, ownsbomPerfAllocTolFrac)
	if res.MedianAllocBytes > ceil {
		t.Errorf("ownsbom allocations regressed: median %d bytes exceeds baseline %d + %.0f%% = %d",
			res.MedianAllocBytes, base.AllocBytes, ownsbomPerfAllocTolFrac*100, ceil)
	}
	if base.EnvironmentDigest == env {
		t.Logf("latency vs same-environment baseline: p50 %s (baseline %dms), p95 %s (baseline %dms)",
			res.LatencyP50, base.LatencyP50Millis, res.LatencyP95, base.LatencyP95Millis)
	} else {
		t.Logf("latency not gated: current environment %s differs from baseline %s", env, base.EnvironmentDigest)
	}
}
