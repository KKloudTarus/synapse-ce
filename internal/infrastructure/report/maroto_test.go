package report

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func sampleEngagement() *engagement.Engagement {
	return &engagement.Engagement{
		Name:   "acme-q3",
		Client: "Acme",
		Scope: engagement.Scope{
			InScope: []engagement.Target{{Kind: engagement.TargetRepo, Value: "/srv/app"}},
		},
	}
}

func sampleFindings() []finding.Finding {
	return []finding.Finding{
		{Title: "CVE-2020-7471 in django@2.2.0", Severity: shared.SeverityCritical, Status: finding.StatusConfirmed, RiskScore: 8.5, KEV: true},
		{Title: "Denied license: GPL-3.0-only", Severity: shared.SeverityHigh, Status: finding.StatusOpen},
	}
}

func TestRenderDeterministic(t *testing.T) {
	at := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	r := NewRenderer()
	a, err := r.Render(context.Background(), sampleEngagement(), sampleFindings(), ports.ReportInsight{HasScan: true, LicensePct: 92, LicenseDetected: 50, EvidenceIntact: true, EvidenceCount: 1, EvidenceHead: "abc123", ReproScore: 85}, at, "v1.2.3")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !bytes.HasPrefix(a, []byte("%PDF-")) {
		t.Fatalf("output is not a PDF: %q", a[:min(8, len(a))])
	}
	// Cross a wall-clock second so a leaking time.Now() (e.g. PDF /ModDate) would
	// diverge the bytes; the renderer must pin every date to the inputs.
	time.Sleep(1100 * time.Millisecond)
	b, err := r.Render(context.Background(), sampleEngagement(), sampleFindings(), ports.ReportInsight{HasScan: true, LicensePct: 92, LicenseDetected: 50, EvidenceIntact: true, EvidenceCount: 1, EvidenceHead: "abc123", ReproScore: 85}, at, "v1.2.3")
	if err != nil {
		t.Fatalf("render (second): %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("render is not byte-deterministic for identical inputs (%d vs %d bytes)", len(a), len(b))
	}
}

func TestRenderEmptyFindings(t *testing.T) {
	at := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	pdf, err := NewRenderer().Render(context.Background(), &engagement.Engagement{Name: "empty"}, nil, ports.ReportInsight{}, at, "v1")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF-")) {
		t.Fatal("output is not a PDF")
	}
}

func TestPDFPostureQualifiesIncompleteEngineCoverage(t *testing.T) {
	partial := ports.ReportInsight{HasScan: true, EngineCoverage: scanrun.EngineCoverage{Status: scanrun.CoverageComplete, Required: 3, Completed: 3}, EngineOutcomes: []scanrun.EngineOutcome{{Engine: "sast", Execution: scanrun.EngineTimedOut, Coverage: scanrun.CoveragePartial, Reason: scanrun.ReasonDeadlineExceeded, Required: true}}}
	if got := executivePosture(0, 1, 1, partial); !bytes.Contains([]byte(got), []byte("ELEVATED RISK")) || !bytes.Contains([]byte(got), []byte("lower bound")) {
		t.Fatalf("high-risk partial posture = %q", got)
	}
	if got := executivePosture(0, 0, 0, partial); !bytes.Contains([]byte(got), []byte("INCONCLUSIVE")) {
		t.Fatalf("zero-finding partial posture = %q", got)
	}
	if got := executivePosture(0, 0, 1, ports.ReportInsight{HasScan: true, EngineCoverage: scanrun.EngineCoverage{Status: scanrun.CoverageComplete, Required: 2, Completed: 2}}); !bytes.Contains([]byte(got), []byte("INCONCLUSIVE")) {
		t.Fatalf("historical unknown posture = %q", got)
	}
}

func TestRenderPDFWithEngineCoverage(t *testing.T) {
	insight := ports.ReportInsight{
		HasScan:        true,
		EngineCoverage: scanrun.EngineCoverage{Status: scanrun.CoveragePartial, Required: 3, Completed: 2},
		EngineOutcomes: []scanrun.EngineOutcome{
			{Engine: "secrets", Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete, Required: true},
			{Engine: "sast", Execution: scanrun.EngineTimedOut, Coverage: scanrun.CoveragePartial, Reason: scanrun.ReasonDeadlineExceeded, Required: true},
		},
	}
	pdf, err := NewRenderer().Render(context.Background(), sampleEngagement(), nil, insight, time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC), "v1")
	if err != nil {
		t.Fatalf("render partial coverage PDF: %v", err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF-")) {
		t.Fatal("output is not a PDF")
	}
	rows := reportEngineOutcomes(insight.EngineOutcomes)
	if len(rows) != 2 || rows[0].Engine != "sast" || rows[0].Reason != scanrun.ReasonDeadlineExceeded {
		t.Fatalf("PDF engine outcome rows = %+v", rows)
	}
}

func TestRenderLongCompletenessWarningKeepsEngineTableBelowWarning(t *testing.T) {
	pdftotext, err := exec.LookPath("pdftotext")
	if err != nil {
		t.Skip("pdftotext is not installed")
	}

	// This is deliberately longer than a single report line. It mirrors an
	// unresolved Maven dependency warning, which must grow before the engine
	// table is placed below it.
	note := "Unresolved build system(s) present: maven. Their dependencies are NOT fully captured (the transitive tree wasn't resolved from source), so this result is INCOMPLETE – a low finding count does NOT mean clean. For a COMPLETE scan: Maven has no lockfile – scan a BUILT artifact (`mvn package`, then scan the produced JAR or `target/`), or resolve the tree first (`mvn dependency:copy-dependencies -DoutputDirectory=target/deps`) and scan that directory."
	insight := ports.ReportInsight{
		HasScan:          true,
		CompletenessNote: note,
		EngineCoverage:   scanrun.EngineCoverage{Status: scanrun.CoveragePartial, Required: 2, Completed: 1},
		EngineOutcomes: []scanrun.EngineOutcome{
			{Engine: "dependency_resolution", Execution: scanrun.EngineCompleted, Coverage: scanrun.CoveragePartial, Reason: scanrun.ReasonDependencyUnresolved, Required: true},
		},
	}
	pdf, err := NewRenderer().Render(context.Background(), sampleEngagement(), nil, insight, time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC), "v1")
	if err != nil {
		t.Fatalf("render report: %v", err)
	}

	words := pdfWordPositions(t, pdftotext, pdf)
	lastWarning, ok := wordPosition(words, "directory.")
	if !ok {
		t.Fatalf("long completeness warning was not rendered: %v", words)
	}
	engineHeader, ok := wordPosition(words, "ENGINE")
	if !ok {
		t.Fatalf("engine table header was not rendered: %v", words)
	}
	if engineHeader.page < lastWarning.page || (engineHeader.page == lastWarning.page && engineHeader.y <= lastWarning.y) {
		t.Fatalf("engine table begins at page %d y=%.2f before warning ends at page %d y=%.2f", engineHeader.page, engineHeader.y, lastWarning.page, lastWarning.y)
	}
}

type pdfWord struct {
	text string
	page int
	y    float64
}

var wordRE = regexp.MustCompile(`<word xMin="[^"]+" yMin="([^"]+)" xMax="[^"]+" yMax="[^"]+">([^<]+)</word>`)

func pdfWordPositions(t *testing.T, pdftotext string, pdf []byte) []pdfWord {
	t.Helper()
	directory := t.TempDir()
	input := filepath.Join(directory, "report.pdf")
	output := filepath.Join(directory, "report.xhtml")
	if err := os.WriteFile(input, pdf, 0o600); err != nil {
		t.Fatalf("write PDF for layout extraction: %v", err)
	}
	if out, err := exec.Command(pdftotext, "-bbox", input, output).CombinedOutput(); err != nil {
		t.Fatalf("extract PDF layout: %v: %s", err, out)
	}
	markup, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read PDF layout: %v", err)
	}
	pages := strings.Split(string(markup), "<page ")
	words := make([]pdfWord, 0)
	for page, markup := range pages[1:] {
		matches := wordRE.FindAllSubmatch([]byte(markup), -1)
		for _, match := range matches {
			y, err := strconv.ParseFloat(string(match[1]), 64)
			if err != nil {
				t.Fatalf("parse word y coordinate %q: %v", match[1], err)
			}
			words = append(words, pdfWord{text: string(match[2]), page: page + 1, y: y})
		}
	}
	return words
}

func wordPosition(words []pdfWord, word string) (pdfWord, bool) {
	for _, candidate := range words {
		if strings.EqualFold(candidate.text, word) {
			return candidate, true
		}
	}
	return pdfWord{}, false
}

func TestPDFPostureQualifiesMixedCurrentAndRetainedResults(t *testing.T) {
	insight := ports.ReportInsight{
		HasScan:                 true,
		ExecutionMode:           "licenses",
		IncludesPreviousResults: true,
		EngineCoverage:          scanrun.EngineCoverage{Status: scanrun.CoverageComplete, Required: 3, Completed: 3},
		EngineOutcomes: []scanrun.EngineOutcome{
			{Engine: "sca", Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete, Required: true},
			{Engine: "licenses", Execution: scanrun.EngineCompleted, Coverage: scanrun.CoverageComplete, Required: true},
		},
	}
	if got := executivePosture(0, 0, 1, insight); !bytes.Contains([]byte(got), []byte("INCONCLUSIVE")) || !bytes.Contains([]byte(got), []byte("previous execution")) {
		t.Fatalf("mixed low-risk PDF posture = %q", got)
	}
	if got := executivePosture(0, 1, 1, insight); !bytes.Contains([]byte(got), []byte("ELEVATED RISK")) || !bytes.Contains([]byte(got), []byte("whole-assessment")) {
		t.Fatalf("mixed high-risk PDF posture = %q", got)
	}
	pdf, err := NewRenderer().Render(context.Background(), sampleEngagement(), nil, insight, time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC), "v1")
	if err != nil || !bytes.HasPrefix(pdf, []byte("%PDF-")) {
		t.Fatalf("render mixed PDF: err=%v prefix=%q", err, pdf[:min(8, len(pdf))])
	}
}
