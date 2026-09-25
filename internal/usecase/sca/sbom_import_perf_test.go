package sca

import (
	"fmt"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/benchperf"
)

// The pinned CycloneDX import workload uses the committed allocation ceiling.
// Hosted CI compares latency and throughput with a same-runner control.

const (
	cdxImportPerfSamples = 20
	cdxImportPerfWarmup  = 3
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
	if err := benchperf.CheckPeakEvidence(res); err != nil {
		t.Fatal(err)
	}
	env := benchperf.EnvironmentDigest()
	t.Logf("cyclonedx-import perf: release=%s env=%s components=%d samples=%d alloc_bytes(median)=%d peak_mem=%d latency_p50=%s latency_p95=%s dataset=%s throughput_ops_per_second=%.6f",
		benchperf.ReleaseDigest(), env, cdxImportPerfComponents, cdxImportPerfSamples, res.MedianAllocBytes, res.PeakMemoryBytes, res.LatencyP50, res.LatencyP95, datasetDigest, res.ThroughputOpsPerSecond)

	base, found, err := benchperf.Load(cdxImportPerfBaselinePath, cdxImportPerfWarmup, cdxImportPerfSamples)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("no committed baseline at %s: the performance ratchet is disabled (commit the measured baseline)", cdxImportPerfBaselinePath)
	}
	if datasetDigest != base.DatasetDigest {
		t.Fatalf("fixture drift: workload digest %s != committed %s (the measured workload changed)", datasetDigest, base.DatasetDigest)
	}
	ceil := base.AllocCeilingBytes
	if res.MedianAllocBytes > ceil {
		t.Errorf("cyclonedx-import allocations regressed: median %d bytes exceeds committed ceiling %d",
			res.MedianAllocBytes, ceil)
	}
	if base.EnvironmentDigest == env {
		t.Logf("latency vs same-environment baseline: p50 %s (baseline %dms), p95 %s (baseline %dms)",
			res.LatencyP50, base.LatencyP50Millis, res.LatencyP95, base.LatencyP95Millis)
	} else {
		t.Logf("latency not gated: current environment %s differs from baseline %s", env, base.EnvironmentDigest)
	}
}
