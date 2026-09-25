package ospkg

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchperf"
)

// This gate catalogs a pinned dpkg fixture independently from image extraction.
// It uses the committed allocation ceiling; hosted CI compares latency and
// throughput with a same-runner control.

const (
	catalogPerfSamples = 20
	catalogPerfWarmup  = 3
	// catalogPerfDebPackages sizes the pinned workload; a fixed count keeps the scanned bytes and the cataloged
	// component set stable across runs and platforms.
	catalogPerfDebPackages  = 1500
	catalogPerfBaselinePath = "../../../../docs/benchmarks/ospkg-catalog-perf.json"
)

// buildCatalogWorkload writes a pinned fixture rootfs: a Debian os-release plus a dpkg status DB with a fixed
// number of installed packages. The content is fully deterministic, so the workload bytes and the cataloged
// component set are identical on every run. It also returns the dataset digest of the fixture content, so the
// gate can assert its live workload matches the committed baseline.
func buildCatalogWorkload(t *testing.T) (rootfs, datasetDigest string) {
	t.Helper()
	var status strings.Builder
	for i := 0; i < catalogPerfDebPackages; i++ {
		fmt.Fprintf(&status, "Package: pkg%04d\nStatus: install ok installed\nVersion: 1.%d.%d-%ddeb12u1\nArchitecture: amd64\nSource: src%04d\n\n",
			i, i%50, i%17, i%9, i)
	}
	osRelease := "ID=debian\nVERSION_ID=\"12\"\n"
	rootfs = writeRootfs(t, map[string]string{
		"etc/os-release":      osRelease,
		"var/lib/dpkg/status": status.String(),
	})
	datasetDigest = benchperf.DatasetDigest("etc/os-release", osRelease, "var/lib/dpkg/status", status.String())
	return rootfs, datasetDigest
}

func TestOSPkgCatalogPerfGate(t *testing.T) {
	if testing.Short() {
		t.Skip("perf gate skipped in -short")
	}
	rootfs, datasetDigest := buildCatalogWorkload(t)
	cat := New()
	catalog := func() int {
		res, err := cat.Catalog(context.Background(), rootfs)
		if err != nil {
			t.Fatalf("catalog: %v", err)
		}
		return len(res.Components)
	}

	// Correctness pre-check: the fixture must catalog exactly the pinned component set, so a perf regression is
	// never masked by fixture drift.
	if components := catalog(); components != catalogPerfDebPackages {
		t.Fatalf("workload cataloged %d components, want %d (fixture drift would make the perf ratchet meaningless)", components, catalogPerfDebPackages)
	}

	res := benchperf.Measure(catalogPerfWarmup, catalogPerfSamples, func() { catalog() })
	if err := benchperf.CheckPeakEvidence(res); err != nil {
		t.Fatal(err)
	}
	env := benchperf.EnvironmentDigest()
	t.Logf("ospkg-catalog perf: release=%s env=%s components=%d samples=%d alloc_bytes(median)=%d peak_mem=%d latency_p50=%s latency_p95=%s dataset=%s throughput_ops_per_second=%.6f",
		benchperf.ReleaseDigest(), env, catalogPerfDebPackages, catalogPerfSamples, res.MedianAllocBytes, res.PeakMemoryBytes, res.LatencyP50, res.LatencyP95, datasetDigest, res.ThroughputOpsPerSecond)

	base, found, err := benchperf.Load(catalogPerfBaselinePath, catalogPerfWarmup, catalogPerfSamples)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("no committed baseline at %s: the performance ratchet is disabled (commit the measured baseline)", catalogPerfBaselinePath)
	}
	if datasetDigest != base.DatasetDigest {
		t.Fatalf("fixture drift: workload digest %s != committed %s (the measured workload changed)", datasetDigest, base.DatasetDigest)
	}
	ceil := base.AllocCeilingBytes
	if res.MedianAllocBytes > ceil {
		t.Errorf("ospkg-catalog allocations regressed: median %d bytes exceeds committed ceiling %d",
			res.MedianAllocBytes, ceil)
	}
	if base.EnvironmentDigest == env {
		t.Logf("latency vs same-environment baseline: p50 %s (baseline %dms), p95 %s (baseline %dms)",
			res.LatencyP50, base.LatencyP50Millis, res.LatencyP95, base.LatencyP95Millis)
	} else {
		t.Logf("latency not gated: current environment %s differs from baseline %s", env, base.EnvironmentDigest)
	}
}
