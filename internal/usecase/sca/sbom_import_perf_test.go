package sca

import (
	"fmt"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchperf"
)

// sbom_import_perf_test.go is the owned SBOM-INGEST performance gate (#1040 A6, the "pinned SBOM" target
// class). It measures repeated parsing of a pinned client-supplied CycloneDX SBOM into the owned component
// model and ratchets on BYTES ALLOCATED per parse via the shared benchperf contract. Allocation is
// deterministic for a given Go toolchain and input, so unlike wall-clock latency it gives a stable
// cross-machine regression signal; the 30% tolerance absorbs the small differences a different Go minor version
// can introduce. Wall-clock latency is recorded and compared only within the same environment digest. The
// baseline lives at docs/benchmarks/cyclonedx-import-perf.json. (This gate is in the usecase layer; it imports
// the infrastructure benchperf package only from a _test.go file, which the architecture test does not police.)

const (
	cdxImportPerfSamples      = 20
	cdxImportPerfWarmup       = 3
	cdxImportPerfAllocTolFrac = 0.30
	// cdxImportPerfComponents sizes the pinned SBOM; a fixed count keeps the parsed component set stable.
	cdxImportPerfComponents   = 1500
	cdxImportPerfBaselinePath = "../../../docs/benchmarks/cyclonedx-import-perf.json"
)

// buildCDXWorkload returns a pinned CycloneDX 1.5 SBOM with a fixed number of components, each carrying a
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
	datasetDigest := benchperf.DatasetDigest("cyclonedx.json", string(data))
	parse := func() int {
		comps, err := ParseCycloneDXComponents(data)
		if err != nil {
			t.Fatalf("parse cyclonedx: %v", err)
		}
		return len(comps)
	}

	if components := parse(); components != cdxImportPerfComponents {
		t.Fatalf("workload parsed %d components, want %d (fixture drift would make the perf ratchet meaningless)", components, cdxImportPerfComponents)
	}

	res := benchperf.Measure(cdxImportPerfWarmup, cdxImportPerfSamples, func() { parse() })
	env := benchperf.EnvironmentDigest()
	t.Logf("cyclonedx-import perf: env=%s components=%d samples=%d alloc_bytes(median)=%d peak_mem=%d latency_p50=%s latency_p95=%s dataset=%s",
		env, cdxImportPerfComponents, cdxImportPerfSamples, res.MedianAllocBytes, res.PeakMemoryBytes, res.LatencyP50, res.LatencyP95, datasetDigest)

	base, found, err := benchperf.Load(cdxImportPerfBaselinePath, cdxImportPerfSamples)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("no committed baseline at %s: the performance ratchet is disabled (commit the measured baseline)", cdxImportPerfBaselinePath)
	}
	if datasetDigest != base.DatasetDigest {
		t.Fatalf("fixture drift: workload digest %s != committed %s (the measured workload changed)", datasetDigest, base.DatasetDigest)
	}
	ceil := benchperf.AllocCeiling(base.AllocBytes, cdxImportPerfAllocTolFrac)
	if res.MedianAllocBytes > ceil {
		t.Errorf("cyclonedx-import allocations regressed: median %d bytes exceeds baseline %d + %.0f%% = %d",
			res.MedianAllocBytes, base.AllocBytes, cdxImportPerfAllocTolFrac*100, ceil)
	}
	if base.EnvironmentDigest == env {
		t.Logf("latency vs same-environment baseline: p50 %s (baseline %dms), p95 %s (baseline %dms)",
			res.LatencyP50, base.LatencyP50Millis, res.LatencyP95, base.LatencyP95Millis)
	} else {
		t.Logf("latency not gated: current environment %s differs from baseline %s", env, base.EnvironmentDigest)
	}
}
