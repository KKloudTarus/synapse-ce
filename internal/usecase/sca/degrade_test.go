package sca

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeSource struct {
	name string
	err  error
	raws []vulnerability.RawFinding
}

func (f fakeSource) Name() string { return f.name }
func (f fakeSource) Scan(context.Context, *sbom.SBOM) ([]vulnerability.RawFinding, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.raws, nil
}

func TestScanWithSources_DegradesOnErrorByDefault(t *testing.T) {
	good := fakeSource{name: "grype", raws: []vulnerability.RawFinding{{Source: "grype", AdvisoryID: "CVE-1"}}}
	bad := fakeSource{name: "osv", err: errors.New("osv.dev 503 service unavailable")}
	svc := &Service{sources: []ports.DetectionSource{bad, good}} // strictSources defaults false
	trace := newScanDebugTrace(func([]ports.ScanDebugEvent) {})
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "x", PURL: "pkg:npm/x@1.0.0"}}}

	raws, warnings, err := svc.scanWithSources(context.Background(), doc, trace)
	if err != nil {
		t.Fatalf("a source error must not abort the scan in non-strict mode: %v", err)
	}
	if len(raws) != 1 || raws[0].AdvisoryID != "CVE-1" {
		t.Fatalf("the healthy source must still contribute; got %+v", raws)
	}
	if len(warnings) != 1 {
		t.Fatalf("the skipped source must record exactly one warning; got %v", warnings)
	}
}

func TestScanWithSources_StrictAborts(t *testing.T) {
	bad := fakeSource{name: "osv", err: errors.New("osv.dev 503")}
	good := fakeSource{name: "grype", raws: []vulnerability.RawFinding{{AdvisoryID: "CVE-1"}}}
	svc := &Service{sources: []ports.DetectionSource{bad, good}, strictSources: true}
	trace := newScanDebugTrace(func([]ports.ScanDebugEvent) {})
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "x", PURL: "pkg:npm/x@1.0.0"}}}

	if _, _, err := svc.scanWithSources(context.Background(), doc, trace); err == nil {
		t.Fatal("strict mode must abort the scan on a source error")
	}
}

func TestScanWithSources_AllHealthy(t *testing.T) {
	a := fakeSource{name: "grype", raws: []vulnerability.RawFinding{{AdvisoryID: "CVE-1"}}}
	b := fakeSource{name: "advisory-store", raws: []vulnerability.RawFinding{{AdvisoryID: "CVE-2"}}}
	svc := &Service{sources: []ports.DetectionSource{a, b}}
	trace := newScanDebugTrace(func([]ports.ScanDebugEvent) {})
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "x", PURL: "pkg:npm/x@1.0.0"}}}

	raws, warnings, err := svc.scanWithSources(context.Background(), doc, trace)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(raws) != 2 {
		t.Fatalf("both sources must contribute; got %d", len(raws))
	}
	if len(warnings) != 0 {
		t.Fatalf("no warnings expected when all sources succeed; got %v", warnings)
	}
}
