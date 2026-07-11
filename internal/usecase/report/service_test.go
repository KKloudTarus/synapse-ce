package report

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Fakes embed the port interface so they satisfy it fully; only the methods the
// report service calls are overridden (the rest panic if unexpectedly invoked).

type fakeEngRepo struct {
	ports.EngagementRepository
	eng *engagement.Engagement
}

func (f fakeEngRepo) GetByID(context.Context, shared.ID) (*engagement.Engagement, error) {
	return f.eng, nil
}
func (f fakeEngRepo) GetByIDInTenant(context.Context, shared.ID, shared.ID) (*engagement.Engagement, error) {
	return f.eng, nil
}

type fakeFindingRepo struct {
	ports.FindingRepository
	list []finding.Finding
}

func (f fakeFindingRepo) ListByEngagement(context.Context, shared.ID) ([]finding.Finding, error) {
	return f.list, nil
}

func (f fakeFindingRepo) ListPublishableByEngagement(context.Context, shared.ID) ([]finding.Finding, error) {
	return finding.Publishable(f.list), nil
}

type fakeInsight struct{ ins ports.ReportInsight }

func (f fakeInsight) ReportInsight(context.Context, shared.ID) (ports.ReportInsight, error) {
	return f.ins, nil
}

type fakeClock struct{}

func (fakeClock) Now() time.Time { return time.Date(2026, 6, 21, 0, 0, 0, 0, time.UTC) }

type fakePDF struct{}

func (fakePDF) Render(context.Context, *engagement.Engagement, []finding.Finding, ports.ReportInsight, time.Time, string) ([]byte, error) {
	return []byte("%PDF-1.7 fake"), nil
}

// capturePDF records the findings handed to the PDF renderer so a test can assert the
// evidence gate ran before the PDF was rendered (the PDF path once skipped it – a publishability leak).
type capturePDF struct{ findings []finding.Finding }

func (c *capturePDF) Render(_ context.Context, _ *engagement.Engagement, fs []finding.Finding, _ ports.ReportInsight, _ time.Time, _ string) ([]byte, error) {
	c.findings = fs
	return []byte("%PDF-1.7 fake"), nil
}

// captureRenderer records the document it was handed so tests can assert assembly.
type captureRenderer struct{ last ports.ReportDocument }

func (c *captureRenderer) Render(_ context.Context, doc ports.ReportDocument) ([]byte, error) {
	c.last = doc
	return []byte("rendered"), nil
}

type fakeRetestRepo struct {
	byFinding map[shared.ID][]finding.Retest
}

func (f fakeRetestRepo) Add(context.Context, finding.Retest) error { return nil }
func (f fakeRetestRepo) ListByEngagementFinding(_ context.Context, _, fid shared.ID) ([]finding.Retest, error) {
	return f.byFinding[fid], nil
}

// fakeEvidence implements ports.ReportEvidenceProvider for the exhibits tests.
type fakeEvidence struct {
	artifacts  []ports.EvidenceArtifact
	bytesBySHA map[string][]byte
}

func (f fakeEvidence) ListArtifacts(context.Context, shared.ID) ([]ports.EvidenceArtifact, error) {
	return f.artifacts, nil
}
func (f fakeEvidence) ArtifactBytes(_ context.Context, _ shared.ID, sha string) ([]byte, error) {
	b, ok := f.bytesBySHA[sha]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return b, nil
}

func newService(insight ports.ReportInsight, findings []finding.Finding) (*Service, *captureRenderer) {
	return newServiceFull(insight, findings, nil, nil)
}

func newServiceWithRetests(insight ports.ReportInsight, findings []finding.Finding, retests map[shared.ID][]finding.Retest) (*Service, *captureRenderer) {
	return newServiceFull(insight, findings, retests, nil)
}

func newServiceFull(insight ports.ReportInsight, findings []finding.Finding, retests map[shared.ID][]finding.Retest, evidence ports.ReportEvidenceProvider) (*Service, *captureRenderer) {
	eng := &engagement.Engagement{Name: "acme-q3", Client: "Acme"}
	svc := NewService(fakeEngRepo{eng: eng}, fakeFindingRepo{list: findings}, fakeRetestRepo{byFinding: retests}, evidence, fakePDF{}, fakeInsight{ins: insight}, fakeClock{}, "v1.2.3")
	cap := &captureRenderer{}
	svc.RegisterFormat(FormatHTML, cap)
	return svc, cap
}

// tinyPNG is a minimal valid 1x1 PNG (deterministic bytes) for exhibit tests.
var tinyPNG = []byte{
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
	0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x62, 0x00, 0x01, 0x00, 0x00,
	0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
	0x42, 0x60, 0x82,
}

func sampleFindings() []finding.Finding {
	return []finding.Finding{
		{ID: "manual:1", Title: "Stored XSS", Severity: shared.SeverityHigh, Status: finding.StatusConfirmed, CWE: "CWE-79", Priority: 4, Description: "desc"},
		{ID: "sca:1", Title: "Old lib", Severity: shared.SeverityMedium, Status: finding.StatusOpen, Priority: 2},
	}
}

func TestRenderUnsupportedFormat(t *testing.T) {
	svc, _ := newService(ports.ReportInsight{}, sampleFindings())
	_, _, _, err := svc.Render(context.Background(), "", "e1", Options{Format: "pdf"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for unregistered format, got %v", err)
	}
}

func TestRenderAssemblesFullDocument(t *testing.T) {
	svc, cap := newService(ports.ReportInsight{HasScan: true, ScanTarget: "/srv/app", Actionable: 1, RawFindings: 2, EvidenceCount: 1, EvidenceIntact: true}, sampleFindings())
	data, ct, sum, err := svc.Render(context.Background(), "", "e1", Options{Format: FormatHTML})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if string(data) != "rendered" || ct == "" || sum == "" {
		t.Fatalf("unexpected render result: data=%q ct=%q sum=%q", data, ct, sum)
	}
	if cap.last.Title != "acme-q3" {
		t.Errorf("title = %q, want engagement name", cap.last.Title)
	}
	// Default = all canonical sections: engagement, scope, methodology, summary, risk,
	// top, findings, details, scan, evidence (full deliverable structure).
	if len(cap.last.Sections) != 10 {
		var got []string
		for _, s := range cap.last.Sections {
			got = append(got, s.Heading)
		}
		t.Fatalf("want 10 sections, got %d: %v", len(cap.last.Sections), got)
	}
	tbl := findTable(cap.last, "Findings Overview")
	if tbl == nil || len(tbl.Rows) != 2 {
		t.Fatalf("findings table should list 2 findings, got %v", tbl)
	}
}

func TestRenderDeliverableSections(t *testing.T) {
	insight := ports.ReportInsight{
		HasScan: true, ScanTarget: "/srv/app", Confident: true, Actionable: 1, RawFindings: 2,
		EvidenceCount: 3, EvidenceIntact: true, EvidenceHead: "abc123", EvidenceAttested: true, EvidenceKeyID: "deadbeefcafe0000",
	}
	findings := []finding.Finding{
		{ID: "sca:1", Title: "RCE in libfoo", Severity: shared.SeverityCritical, Status: finding.StatusConfirmed, Priority: 1, KEV: true},
		{ID: "manual:1", Title: "Stored XSS", Severity: shared.SeverityHigh, Status: finding.StatusOpen, Priority: 3},
	}
	svc, cap := newService(insight, findings)
	if _, _, _, err := svc.Render(context.Background(), "", "e1", Options{Format: FormatHTML}); err != nil {
		t.Fatalf("render: %v", err)
	}

	// Headings present and in canonical order.
	wantOrder := []string{
		"Engagement Summary", "Scope Statement", "Methodology", "Executive Summary",
		"Risk Overview", "Top Findings", "Findings Overview", "Finding Details",
		"Scan & SBOM Insight", "Evidence & Chain of Custody",
	}
	var gotOrder []string
	for _, s := range cap.last.Sections {
		gotOrder = append(gotOrder, s.Heading)
	}
	if len(gotOrder) != len(wantOrder) {
		t.Fatalf("section headings = %v", gotOrder)
	}
	for i := range wantOrder {
		if gotOrder[i] != wantOrder[i] {
			t.Errorf("section %d = %q, want %q", i, gotOrder[i], wantOrder[i])
		}
	}

	// Engagement summary carries the client.
	if tbl := findTable(cap.last, "Engagement Summary"); tbl == nil || !rowsContain(tbl, "Acme") {
		t.Errorf("engagement summary must name the client: %+v", tbl)
	}
	// Risk overview ranks the KEV finding; top findings flags KEV.
	if tbl := findTable(cap.last, "Top Findings"); tbl == nil || !rowsContain(tbl, "yes") {
		t.Errorf("top findings must flag the KEV finding: %+v", tbl)
	}
	// Evidence section surfaces the origin attestation key id.
	if !sectionMentions(cap.last, "Evidence & Chain of Custody", "deadbeefcafe0000") {
		t.Error("evidence section must surface the attestation key id")
	}
	// Methodology states the prioritization model (KEV → EPSS × CVSS).
	if !sectionMentions(cap.last, "Methodology", "EPSS") {
		t.Error("methodology must state the EPSS-based prioritization")
	}
}

func TestRenderStatusFilterAndTitle(t *testing.T) {
	svc, cap := newService(ports.ReportInsight{}, sampleFindings())
	_, _, _, err := svc.Render(context.Background(), "", "e1", Options{Format: FormatHTML, Statuses: []string{"confirmed"}, Title: "Custom Title"})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if cap.last.Title != "Custom Title" {
		t.Errorf("title override not applied: %q", cap.last.Title)
	}
	tbl := findTable(cap.last, "Findings Overview")
	if tbl == nil || len(tbl.Rows) != 1 || tbl.Rows[0][0] != "manual:1" {
		t.Fatalf("status filter should keep only the confirmed finding, got %v", tbl)
	}
}

func TestRenderSectionSelection(t *testing.T) {
	svc, cap := newService(ports.ReportInsight{}, sampleFindings())
	_, _, _, err := svc.Render(context.Background(), "", "e1", Options{Format: FormatHTML, Sections: []string{SectionSummary}})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if len(cap.last.Sections) != 1 || cap.last.Sections[0].Heading != "Executive Summary" {
		t.Fatalf("section selection failed: %+v", cap.last.Sections)
	}
}

func TestRenderBlocksTamperedEvidence(t *testing.T) {
	svc, _ := newService(ports.ReportInsight{HasScan: true, EvidenceCount: 1, EvidenceIntact: false}, sampleFindings())
	_, _, _, err := svc.Render(context.Background(), "", "e1", Options{Format: FormatHTML})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("tampered evidence must block the report, got %v", err)
	}
}

func TestGeneratePDFStillWorks(t *testing.T) {
	svc, _ := newService(ports.ReportInsight{}, sampleFindings())
	pdf, sum, err := svc.Generate(context.Background(), "", "e1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(pdf) == 0 || sum == "" {
		t.Fatal("empty PDF or seal")
	}
}

func TestRenderRejectsUnknownType(t *testing.T) {
	svc, _ := newService(ports.ReportInsight{}, sampleFindings())
	_, _, _, err := svc.Render(context.Background(), "", "e1", Options{Format: FormatHTML, Type: "marketing"})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown report type must be rejected, got %v", err)
	}
}

func TestExternalReportFramesAndDropsScanSection(t *testing.T) {
	insight := ports.ReportInsight{HasScan: true, ScanTarget: "/srv/app", Actionable: 1, RawFindings: 1}
	svc, cap := newService(insight, sampleFindings())
	if _, _, _, err := svc.Render(context.Background(), "", "e1", Options{Format: FormatHTML, Type: TypeExternal}); err != nil {
		t.Fatalf("render: %v", err)
	}
	if cap.last.Title != "External Security Assessment" {
		t.Errorf("external report title = %q", cap.last.Title)
	}
	// The external set omits the SCA-specific scan section even though a scan ran.
	if findSection(cap.last, "Scan & SBOM Insight") != nil {
		t.Error("external assessment must not include the SCA scan section")
	}
	if !sectionMentions(cap.last, "Executive Summary", "EXTERNAL") {
		t.Error("external posture line missing from the executive summary")
	}
	if !sectionMentions(cap.last, "Methodology", "external (internet) vantage") {
		t.Error("external methodology narrative missing")
	}
}

func TestInternalReportFraming(t *testing.T) {
	svc, cap := newService(ports.ReportInsight{}, sampleFindings())
	if _, _, _, err := svc.Render(context.Background(), "", "e1", Options{Format: FormatHTML, Type: TypeInternal}); err != nil {
		t.Fatalf("render: %v", err)
	}
	if cap.last.Title != "Internal Network Assessment" {
		t.Errorf("internal report title = %q", cap.last.Title)
	}
	if !sectionMentions(cap.last, "Executive Summary", "INTERNAL") {
		t.Error("internal posture line missing")
	}
}

func TestRetestReportSurfacesRemediationVerdicts(t *testing.T) {
	findings := []finding.Finding{
		{ID: "f1", Title: "SQLi in login", Severity: shared.SeverityCritical, Status: finding.StatusRemediated},
		{ID: "f2", Title: "Weak TLS", Severity: shared.SeverityMedium, Status: finding.StatusConfirmed},
		{ID: "f3", Title: "No retest yet", Severity: shared.SeverityLow, Status: finding.StatusOpen},
	}
	when := time.Date(2026, 6, 20, 9, 0, 0, 0, time.UTC)
	retests := map[shared.ID][]finding.Retest{
		// f1 was re-tested twice; the latest verdict (remediated) wins.
		"f1": {
			{FindingID: "f1", Outcome: finding.RetestStillVulnerable, Tester: "alice", At: when},
			{FindingID: "f1", Outcome: finding.RetestRemediated, Tester: "alice", At: when.Add(24 * time.Hour)},
		},
		"f2": {{FindingID: "f2", Outcome: finding.RetestStillVulnerable, Tester: "bob", At: when}},
	}
	svc, cap := newServiceWithRetests(ports.ReportInsight{}, findings, retests)
	if _, _, _, err := svc.Render(context.Background(), "", "e1", Options{Format: FormatHTML, Type: TypeRetest}); err != nil {
		t.Fatalf("render: %v", err)
	}
	if cap.last.Title != "Remediation Retest Report" {
		t.Errorf("retest report title = %q", cap.last.Title)
	}
	tbl := findTable(cap.last, "Remediation Status")
	if tbl == nil {
		t.Fatal("retest report must have a Remediation Status section")
	}
	// Only the two re-tested findings appear (f3 has no retest); latest verdict wins.
	if len(tbl.Rows) != 2 {
		t.Fatalf("remediation table should list the 2 re-tested findings, got %d: %v", len(tbl.Rows), tbl.Rows)
	}
	if !rowsContain(tbl, "Remediated") || !rowsContain(tbl, "Still vulnerable") {
		t.Errorf("remediation verdicts not rendered: %v", tbl.Rows)
	}
	// Summary line counts the verdicts and flags remaining exposure.
	if !sectionMentions(cap.last, "Remediation Status", "1 remediated, 1 still vulnerable") {
		t.Errorf("remediation summary line wrong: %+v", findSection(cap.last, "Remediation Status").Paragraphs)
	}
	if !sectionMentions(cap.last, "Remediation Status", "remain exploitable") {
		t.Error("retest must flag still-vulnerable findings")
	}
}

func TestRetestReportWithoutVerdictsOmitsRemediation(t *testing.T) {
	// Retest type but no retest data → the remediation section is omitted, not empty.
	svc, cap := newServiceWithRetests(ports.ReportInsight{}, sampleFindings(), nil)
	if _, _, _, err := svc.Render(context.Background(), "", "e1", Options{Format: FormatHTML, Type: TypeRetest}); err != nil {
		t.Fatalf("render: %v", err)
	}
	if findSection(cap.last, "Remediation Status") != nil {
		t.Error("a retest report with no verdicts must omit the Remediation Status section")
	}
}

func TestExhibitsEmbedRasterImagesOnly(t *testing.T) {
	ev := fakeEvidence{
		artifacts: []ports.EvidenceArtifact{
			{Kind: "screenshot", Filename: "login.png", SHA256: "aaa", Size: len(tinyPNG)},
			{Kind: "http", Filename: "request.txt", SHA256: "bbb", Size: 5}, // not an image
		},
		bytesBySHA: map[string][]byte{
			"aaa": tinyPNG,
			"bbb": []byte("plain"),
		},
	}
	svc, cap := newServiceFull(ports.ReportInsight{}, sampleFindings(), nil, ev)
	if _, _, _, err := svc.Render(context.Background(), "", "e1", Options{Format: FormatHTML, Type: TypeExternal}); err != nil {
		t.Fatalf("render: %v", err)
	}
	sec := findSection(cap.last, "Evidence Exhibits")
	if sec == nil {
		t.Fatal("expected an Evidence Exhibits section")
	}
	if len(sec.Images) != 1 {
		t.Fatalf("only the raster image must be embedded, got %d images", len(sec.Images))
	}
	img := sec.Images[0]
	if img.MIME != "image/png" || len(img.Data) == 0 {
		t.Errorf("embedded image wrong: mime=%q bytes=%d", img.MIME, len(img.Data))
	}
	if !strings.Contains(img.Caption, "login.png") || !strings.Contains(img.Caption, "sha256 aaa") {
		t.Errorf("caption should name the file + chain sha: %q", img.Caption)
	}
}

func TestExhibitsRespectTotalByteBudget(t *testing.T) {
	// One ~5 MiB png-magic blob shared by many shas (so the test holds ~5 MiB, not
	// hundreds): the per-image cap passes, but the running total trips the budget.
	big := make([]byte, maxExhibitBytes-100)
	copy(big, tinyPNG) // PNG magic up front → sniffs as image/png
	const n = 40       // 40 x ~5 MiB = ~200 MiB logical, over the 128 MiB total budget
	ev := fakeEvidence{bytesBySHA: map[string][]byte{}}
	for i := 0; i < n; i++ {
		sha := fmt.Sprintf("sha%02d", i)
		ev.artifacts = append(ev.artifacts, ports.EvidenceArtifact{Kind: "screenshot", Filename: sha + ".png", SHA256: sha, Size: len(big)})
		ev.bytesBySHA[sha] = big
	}
	svc, cap := newServiceFull(ports.ReportInsight{}, sampleFindings(), nil, ev)
	if _, _, _, err := svc.Render(context.Background(), "", "e1", Options{Format: FormatHTML, Type: TypeExternal}); err != nil {
		t.Fatalf("render: %v", err)
	}
	sec := findSection(cap.last, "Evidence Exhibits")
	if sec == nil {
		t.Fatal("expected an Evidence Exhibits section")
	}
	// 25 x ~5 MiB fits under 128 MiB; the 26th would exceed it → capped well below n.
	want := maxExhibitTotalBytes / len(big)
	if len(sec.Images) != want {
		t.Fatalf("total-byte budget should cap embedding at %d images, got %d", want, len(sec.Images))
	}
	if len(sec.Images) >= n {
		t.Error("budget did not bound the embedded images")
	}
}

func TestExhibitsOmittedWhenNoImages(t *testing.T) {
	// Provider with only non-image artifacts → exhibits section omitted.
	ev := fakeEvidence{
		artifacts:  []ports.EvidenceArtifact{{Kind: "http", Filename: "r.txt", SHA256: "x", Size: 3}},
		bytesBySHA: map[string][]byte{"x": []byte("abc")},
	}
	svc, cap := newServiceFull(ports.ReportInsight{}, sampleFindings(), nil, ev)
	if _, _, _, err := svc.Render(context.Background(), "", "e1", Options{Format: FormatHTML, Type: TypeExternal}); err != nil {
		t.Fatalf("render: %v", err)
	}
	if findSection(cap.last, "Evidence Exhibits") != nil {
		t.Error("exhibits section must be omitted when there are no embeddable images")
	}
}

func TestExhibitsSkippedWhenDeselected(t *testing.T) {
	// Section not requested → the provider is not even consulted (no images fetched).
	ev := fakeEvidence{
		artifacts:  []ports.EvidenceArtifact{{Kind: "screenshot", Filename: "a.png", SHA256: "aaa", Size: len(tinyPNG)}},
		bytesBySHA: map[string][]byte{"aaa": tinyPNG},
	}
	svc, cap := newServiceFull(ports.ReportInsight{}, sampleFindings(), nil, ev)
	if _, _, _, err := svc.Render(context.Background(), "", "e1", Options{Format: FormatHTML, Sections: []string{SectionFindings}}); err != nil {
		t.Fatalf("render: %v", err)
	}
	if findSection(cap.last, "Evidence Exhibits") != nil {
		t.Error("exhibits must not appear when the section is not selected")
	}
}

func TestRenderDeterministicAcrossRuns(t *testing.T) {
	// Same inputs → byte-identical document assembly.
	insight := ports.ReportInsight{HasScan: true, ScanTarget: "/srv/app", Actionable: 1, RawFindings: 2, EvidenceCount: 1, EvidenceIntact: true}
	a, ca := newService(insight, sampleFindings())
	b, cb := newService(insight, sampleFindings())
	if _, _, sa, err := a.Render(context.Background(), "", "e1", Options{Format: FormatHTML, Type: TypeExternal}); err != nil {
		t.Fatal(err)
	} else if _, _, sb, err := b.Render(context.Background(), "", "e1", Options{Format: FormatHTML, Type: TypeExternal}); err != nil {
		t.Fatal(err)
	} else if sa != sb {
		t.Errorf("same inputs must seal to the same SHA-256: %s vs %s", sa, sb)
	}
	if len(ca.last.Sections) != len(cb.last.Sections) {
		t.Error("section count must be stable across runs")
	}
}

func findTable(doc ports.ReportDocument, heading string) *ports.ReportTable {
	for _, s := range doc.Sections {
		if s.Heading == heading {
			return s.Table
		}
	}
	return nil
}

// findSection returns the section with the given heading, or nil.
func findSection(doc ports.ReportDocument, heading string) *ports.ReportSection {
	for i := range doc.Sections {
		if doc.Sections[i].Heading == heading {
			return &doc.Sections[i]
		}
	}
	return nil
}

// rowsContain reports whether any cell in the table equals want.
func rowsContain(tbl *ports.ReportTable, want string) bool {
	for _, row := range tbl.Rows {
		for _, cell := range row {
			if cell == want {
				return true
			}
		}
	}
	return false
}

// sectionMentions reports whether the named section has a paragraph containing sub.
func sectionMentions(doc ports.ReportDocument, heading, sub string) bool {
	for _, s := range doc.Sections {
		if s.Heading != heading {
			continue
		}
		for _, p := range s.Paragraphs {
			if strings.Contains(p, sub) {
				return true
			}
		}
	}
	return false
}

// TestDetailsSectionCompliance: a finding's CWE surfaces its curated compliance controls in the
// finding-details meta line (a deterministic table lookup – no LLM in the report path).
// An unmapped or CWE-less finding carries no compliance tag.
func TestDetailsSectionCompliance(t *testing.T) {
	findings := []finding.Finding{
		{ID: "sast:1", Title: "SQLi", Severity: shared.SeverityHigh, Status: finding.StatusConfirmed, CWE: "CWE-89", Priority: 4},
		{ID: "sast:2", Title: "SSRF", Severity: shared.SeverityMedium, Status: finding.StatusConfirmed, CWE: "CWE-918", Priority: 3},
		{ID: "manual:9", Title: "No CWE", Severity: shared.SeverityLow, Status: finding.StatusOpen, Priority: 1},
	}
	sec, ok := detailsSection(findings)
	if !ok {
		t.Fatal("detailsSection should produce a section")
	}
	joined := strings.Join(sec.Paragraphs, "\n")

	// CWE-89 (injection) → OWASP A03 + PCI 6.2.4 + ISO A.8.28, all on a Compliance line.
	for _, want := range []string{"Compliance: ", "OWASP-2021 A03:2021", "PCI-DSS-4.0 6.2.4", "ISO-27001-2022 A.8.28"} {
		if !strings.Contains(joined, want) {
			t.Errorf("CWE-89 finding details must include %q; got:\n%s", want, joined)
		}
	}
	// CWE-918 (SSRF) → OWASP A10 + ISO, but NOT PCI (not enumerated by 6.2.4 – verified in the domain test).
	if !strings.Contains(joined, "OWASP-2021 A10:2021") {
		t.Errorf("CWE-918 must map to OWASP A10; got:\n%s", joined)
	}
	// Exactly the two CWE-bearing findings emit a Compliance line; the CWE-less one does not.
	if n := strings.Count(joined, "Compliance: "); n != 2 {
		t.Errorf("exactly the 2 mapped findings should emit a Compliance line, got %d:\n%s", n, joined)
	}
}
