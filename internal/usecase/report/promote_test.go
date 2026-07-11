package report

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestPromotableExcludesUnprovenExploitation pins the publishability rule in the report path: an
// unproven AI/exploitation finding (below the evidence bar) is never published, while SCA/
// manual/recon findings and a proven exploitation finding are kept.
func TestPromotableExcludesUnprovenExploitation(t *testing.T) {
	in := []finding.Finding{
		{ID: "sca", Kind: finding.KindSCA, Title: "CVE", EvidenceScore: 0},     // not gated → kept
		{ID: "manual", Kind: finding.KindManual, Title: "note"},                // not gated → kept
		{ID: "exp-unproven", Kind: finding.KindExploitation, EvidenceScore: 0}, // gated, below bar → dropped
		{ID: "exp-low", Kind: finding.KindExploitation, EvidenceScore: 74},     // below bar → dropped
		{ID: "exp-proven", Kind: finding.KindExploitation, EvidenceScore: 75},  // at bar → kept
	}
	got := map[string]bool{}
	for _, f := range finding.Publishable(in) {
		got[f.ID.String()] = true
	}
	if !got["sca"] || !got["manual"] || !got["exp-proven"] {
		t.Errorf("must keep sca, manual, and proven exploitation: %v", got)
	}
	if got["exp-unproven"] || got["exp-low"] {
		t.Errorf("must drop unproven exploitation findings: %v", got)
	}
	if len(got) != 3 {
		t.Errorf("expected 3 promotable findings, got %d", len(got))
	}
}

// TestEvidenceGateAppliesToEveryReportFormat is the regression guard for the PDF leak: the
// evidence gate must run for EVERY format, not only HTML/DOCX. Before the fix, Generate (PDF)
// handed raw findings straight to the renderer, so an unproven exploitation finding was sealed
// into the primary client deliverable. It drives the real Generate + Render entry points (a
// unit test on promotable() alone would NOT have caught it – promotable() was correct; it just
// was not called on the PDF path).
func TestEvidenceGateAppliesToEveryReportFormat(t *testing.T) {
	findings := []finding.Finding{
		{ID: "sca:1", Kind: finding.KindSCA, Title: "CVE-1", Severity: shared.SeverityHigh, Status: finding.StatusOpen, Priority: 3},
		{ID: "exp:proven", Kind: finding.KindExploitation, Title: "Proven RCE", Severity: shared.SeverityCritical, Status: finding.StatusConfirmed, EvidenceScore: 80, Priority: 1},
		{ID: "exp:unproven", Kind: finding.KindExploitation, Title: "Unproven RCE", Severity: shared.SeverityCritical, Status: finding.StatusOpen, EvidenceScore: 10, Priority: 1},
	}
	eng := &engagement.Engagement{Name: "acme", Client: "Acme"}
	pdf := &capturePDF{}
	svc := NewService(fakeEngRepo{eng: eng}, fakeFindingRepo{list: findings}, nil, nil, pdf, fakeInsight{}, fakeClock{}, "v1")
	html := &captureRenderer{}
	svc.RegisterFormat(FormatHTML, html)

	// PDF path (Generate): assert the renderer received the gated set.
	if _, _, err := svc.Generate(context.Background(), "", "e1"); err != nil {
		t.Fatalf("generate pdf: %v", err)
	}
	gotPDF := map[string]bool{}
	for _, f := range pdf.findings {
		gotPDF[f.ID.String()] = true
	}
	if gotPDF["exp:unproven"] {
		t.Error("PDF leaked an unproven exploitation finding")
	}
	if !gotPDF["sca:1"] || !gotPDF["exp:proven"] {
		t.Errorf("PDF must still include publishable findings: %v", gotPDF)
	}

	// HTML path (Render): the findings table must not list the unproven finding.
	if _, _, _, err := svc.Render(context.Background(), "", "e1", Options{Format: FormatHTML}); err != nil {
		t.Fatalf("render html: %v", err)
	}
	tbl := findTable(html.last, "Findings Overview")
	if tbl == nil {
		t.Fatal("html report missing Findings Overview")
	}
	if rowsContain(tbl, "exp:unproven") {
		t.Error("HTML leaked an unproven exploitation finding")
	}
	if !rowsContain(tbl, "sca:1") || !rowsContain(tbl, "exp:proven") {
		t.Errorf("HTML must still include publishable findings: %v", tbl.Rows)
	}
}
