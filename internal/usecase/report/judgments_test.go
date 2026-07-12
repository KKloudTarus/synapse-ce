package report

import (
	"context"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// fakeJudgments is a stand-in judgmentReader returning a fixed list.
type fakeJudgments struct {
	list []judgment.Judgment
	err  error
}

func (f fakeJudgments) ListByEngagement(context.Context, shared.ID) ([]judgment.Judgment, error) {
	return f.list, f.err
}

func acceptedNarrative(subjectID shared.ID, drivers []string, priority int) judgment.Judgment {
	return judgment.Judgment{
		Capability: judgment.CapRiskNarrative, State: judgment.StateConfirmed,
		SubjectKind: judgment.SubjectFinding, SubjectID: subjectID,
		Claim: judgment.RiskNarrativeClaim{Drivers: drivers, Priority: priority},
	}
}

func acceptedCorrelation(subjectID shared.ID, reporters, missing []string) judgment.Judgment {
	return judgment.Judgment{
		Capability: judgment.CapCorrelation, State: judgment.StateConfirmed,
		SubjectKind: judgment.SubjectComponent, SubjectID: subjectID,
		Claim: judgment.CorrelationClaim{Reporters: reporters, Missing: missing},
	}
}

// TestReportProjectsAcceptedJudgments proves ACCEPTED risk-narrative + correlation judgments surface in
// the scan section as closed tokens (drivers/priority, reporter/missing lists) — no model prose.
func TestReportProjectsAcceptedJudgments(t *testing.T) {
	svc, cap := newService(ports.ReportInsight{HasScan: true, ScanTarget: "/srv/app", Actionable: 1}, sampleFindings())
	svc.SetJudgments(fakeJudgments{list: []judgment.Judgment{
		acceptedNarrative("manual:1", []string{"kev", "epss-high"}, 4),
		acceptedCorrelation("pkg:npm/left-pad@1.0.0", []string{"osv", "grype"}, []string{"owned"}),
	}})

	if _, _, _, err := svc.Render(context.Background(), "", "e1", Options{Format: FormatHTML}); err != nil {
		t.Fatalf("render: %v", err)
	}
	sec := findSection(cap.last, "Scan & SBOM Insight")
	if sec == nil {
		t.Fatal("scan section missing")
	}
	joined := strings.Join(sec.Paragraphs, "\n")
	wantRisk := "AI risk rationale — finding:manual:1: priority 4, drivers kev, epss-high."
	wantCorr := "Cross-check — component:pkg:npm/left-pad@1.0.0: reported by [osv, grype]; not reported by [owned]."
	if !strings.Contains(joined, wantRisk) {
		t.Errorf("risk rationale token missing.\n got: %q\nwant substr: %q", joined, wantRisk)
	}
	if !strings.Contains(joined, wantCorr) {
		t.Errorf("correlation token missing.\n got: %q\nwant substr: %q", joined, wantCorr)
	}
}

// TestReportJudgmentSectionAppearsWithoutScan proves the projection alone (no SBOM scan) still emits the
// section, so accepted AI judgments are never silently dropped from a non-scan engagement.
func TestReportJudgmentSectionAppearsWithoutScan(t *testing.T) {
	svc, cap := newService(ports.ReportInsight{}, sampleFindings()) // HasScan == false
	svc.SetJudgments(fakeJudgments{list: []judgment.Judgment{
		acceptedNarrative("manual:1", []string{"kev"}, 3),
	}})
	if _, _, _, err := svc.Render(context.Background(), "", "e1", Options{Format: FormatHTML}); err != nil {
		t.Fatalf("render: %v", err)
	}
	if findSection(cap.last, "Scan & SBOM Insight") == nil {
		t.Fatal("scan section should appear when only accepted judgments are present")
	}
}

// TestReportSkipsUnacceptedAndSortsDeterministically proves (a) proposed / refuted judgments are excluded
// (only human-accepted ones publish) and (b) output order is byte-reproducible (sorted by subject).
func TestReportSkipsUnacceptedAndSortsDeterministically(t *testing.T) {
	proposed := acceptedNarrative("manual:9", []string{"kev"}, 5)
	proposed.State = judgment.StateProposed // NOT publishable
	refuted := acceptedNarrative("manual:8", []string{"kev"}, 5)
	refuted.State = judgment.StateRefuted // NOT publishable

	var insight ports.ReportInsight
	insight.HasScan = false
	r := fakeJudgments{list: []judgment.Judgment{
		acceptedNarrative("manual:3", []string{"epss-high"}, 2),
		proposed,
		acceptedNarrative("manual:1", []string{"kev"}, 4),
		refuted,
	}}
	projectAcceptedJudgments(context.Background(), r, "e1", &insight)

	if len(insight.RiskRationales) != 2 {
		t.Fatalf("want 2 accepted rationales (proposed+refuted excluded), got %d", len(insight.RiskRationales))
	}
	if insight.RiskRationales[0].Subject != "finding:manual:1" || insight.RiskRationales[1].Subject != "finding:manual:3" {
		t.Errorf("rationales not sorted by subject: %+v", insight.RiskRationales)
	}
}

// TestReportProjectionIsByteReproducible proves the projection is TOTALLY ordered: multiple accepted
// judgments on the SAME subject (same priority, different drivers) sort deterministically regardless of
// the store's return order — reports are hash-sealed, so an unstable permutation would change the bytes.
func TestReportProjectionIsByteReproducible(t *testing.T) {
	// Same subject + same priority, differing only in Drivers — the tie-break case that an unstable,
	// non-total sort would permute.
	a := acceptedNarrative("manual:1", []string{"kev"}, 3)
	b := acceptedNarrative("manual:1", []string{"epss-high"}, 3)
	c := acceptedNarrative("manual:1", []string{"reachable"}, 3)

	order1 := []judgment.Judgment{a, b, c}
	order2 := []judgment.Judgment{c, a, b} // same set, different store order

	var i1, i2 ports.ReportInsight
	projectAcceptedJudgments(context.Background(), fakeJudgments{list: order1}, "e1", &i1)
	projectAcceptedJudgments(context.Background(), fakeJudgments{list: order2}, "e1", &i2)

	if len(i1.RiskRationales) != 3 {
		t.Fatalf("want 3 rationales, got %d", len(i1.RiskRationales))
	}
	for k := range i1.RiskRationales {
		if strings.Join(i1.RiskRationales[k].Drivers, ",") != strings.Join(i2.RiskRationales[k].Drivers, ",") {
			t.Fatalf("projection order differs by input order at %d: %v vs %v", k, i1.RiskRationales, i2.RiskRationales)
		}
	}
	// Concretely: sorted by joined drivers → epss-high, kev, reachable.
	got := []string{
		strings.Join(i1.RiskRationales[0].Drivers, ","),
		strings.Join(i1.RiskRationales[1].Drivers, ","),
		strings.Join(i1.RiskRationales[2].Drivers, ","),
	}
	want := []string{"epss-high", "kev", "reachable"}
	for k := range want {
		if got[k] != want[k] {
			t.Errorf("tie-break order[%d] = %q, want %q", k, got[k], want[k])
		}
	}
}

// TestReportJudgmentReadErrorIsBestEffort proves a judgment-store read error leaves the report sections
// empty rather than failing the whole render (deliverables must not depend on the optional AI layer).
func TestReportJudgmentReadErrorIsBestEffort(t *testing.T) {
	var insight ports.ReportInsight
	projectAcceptedJudgments(context.Background(), fakeJudgments{err: shared.ErrNotFound}, "e1", &insight)
	if len(insight.RiskRationales) != 0 || len(insight.CorrelationNotes) != 0 {
		t.Fatalf("read error should leave sections empty, got %+v / %+v", insight.RiskRationales, insight.CorrelationNotes)
	}
}
