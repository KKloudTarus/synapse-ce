package sca

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// capabilityGapMisconfigScanner reports a capability that could not evaluate its input, with findings from
// the raw scan that remained available.
type capabilityGapMisconfigScanner struct {
	report ports.MisconfigScanReport
}

func (*capabilityGapMisconfigScanner) Name() string { return "capability-gap-iac" }

func (s *capabilityGapMisconfigScanner) ScanConfigs(ctx context.Context, path string) ([]ports.MisconfigRawFinding, error) {
	report, err := s.ScanConfigsReport(ctx, path)
	return report.Findings, err
}

func (s *capabilityGapMisconfigScanner) ScanConfigsReport(context.Context, string) (ports.MisconfigScanReport, error) {
	return s.report, nil
}

// An input a required capability could not evaluate makes IaC coverage partial, so --require-complete
// rejects the run. Execution completing is not the same as the input being assessed.
func TestIaCCapabilityGapMakesCoveragePartial(t *testing.T) {
	svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
	svc.SetMisconfigScanner(&capabilityGapMisconfigScanner{report: ports.MisconfigScanReport{
		UnassessedInputs:  2,
		UnassessedReasons: []string{"kustomization rendering is not enabled for this scan, so overlay patches were not applied"},
	}})
	result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
	if err != nil {
		t.Fatal(err)
	}
	outcome, ok := result.engineOutcome("iac")
	if !ok {
		t.Fatal("the iac engine must carry an outcome")
	}
	if outcome.Coverage != scanrun.CoveragePartial || outcome.Reason != scanrun.ReasonAnalysisIncomplete {
		t.Fatalf("iac outcome %+v, want partial/analysis_incomplete", outcome)
	}
	if outcome.Counts[scanrun.MeasureFilesUnscanned] != 2 {
		t.Fatalf("the unassessed input count must be measured, got %v", outcome.Counts)
	}
	if result.EngineCoverage.Complete() {
		t.Fatal("an unassessed capability input must not read as complete coverage")
	}
	var found bool
	for _, w := range result.SourceWarnings {
		if strings.Contains(w, "NOT evaluated by the capability that owns them") && strings.Contains(w, "overlay patches") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the warning must name the capability and what to enable, got %q", result.SourceWarnings)
	}
}

// An attribute inside the documented evaluation contract that did not resolve is reported, and coverage
// stays complete: the contract is published, and the reader is told where evaluation stopped.
func TestIaCUnresolvedAttributesAreReportedWithoutClaimingAGap(t *testing.T) {
	svc := newSvc(&fakeEngRepo{eng: engagementWithScope(t, "myrepo")}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAcquirer{dir: t.TempDir()}, &fakeAudit{}, &fakeDetector{})
	svc.SetMisconfigScanner(&capabilityGapMisconfigScanner{report: ports.MisconfigScanReport{
		UnresolvedInputs: []string{"main.tf:12: cidr_blocks"},
	}})
	result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: "myrepo"})
	if err != nil {
		t.Fatal(err)
	}
	outcome, _ := result.engineOutcome("iac")
	if outcome.Coverage != scanrun.CoverageComplete {
		t.Fatalf("iac outcome %+v, want complete coverage", outcome)
	}
	var found bool
	for _, w := range result.SourceWarnings {
		if strings.Contains(w, "did not resolve to a value") && strings.Contains(w, "main.tf:12: cidr_blocks") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the warning must name the unresolved attribute, got %q", result.SourceWarnings)
	}
}
