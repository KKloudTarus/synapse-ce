// Package report renders engagement PDF reports with maroto v2. The output is
// deterministic – the PDF creation-date metadata is
// pinned to the caller-supplied generatedAt and the content is a pure function
// of the stored engagement + findings (no LLM in the report path).
package report

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/config"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"
	"github.com/phpdave11/gofpdf"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// gofpdf assigns font/image object ids by Go map-iteration order unless
// catalog-sort is enabled, which would make the PDF bytes – and thus the SHA-256
// seal – non-reproducible from the same data. Enable it process-wide so every
// report is deterministic (maroto builds its Fpdf internally, inheriting this).
func init() { gofpdf.SetDefaultCatalogSort(true) }

// Renderer implements ports.ReportRenderer using maroto v2.
type Renderer struct{}

// NewRenderer returns a PDF report renderer.
func NewRenderer() *Renderer { return &Renderer{} }

var _ ports.ReportRenderer = (*Renderer)(nil)

// Render builds the engagement report PDF. It never calls an LLM or external
// service – the document is derived solely from eng + findings.
func (Renderer) Render(_ context.Context, eng *engagement.Engagement, findings []finding.Finding, insight ports.ReportInsight, generatedAt time.Time, version string) ([]byte, error) {
	at := generatedAt.UTC()
	cfg := config.NewBuilder().WithCreationDate(at).Build()
	m := maroto.New(cfg)

	// Title block.
	m.AddRow(16, text.NewCol(12, "Security Assessment Report", props.Text{Size: 20, Style: fontstyle.Bold, Align: align.Center}))
	m.AddRow(8, text.NewCol(12, nonEmpty(eng.Name, "Untitled engagement"), props.Text{Size: 13, Style: fontstyle.Bold, Align: align.Center}))
	sub := "Generated " + at.Format("2006-01-02 15:04 UTC") + "  ·  Synapse " + version
	if eng.Client != "" {
		sub = "Client: " + eng.Client + "  ·  " + sub
	}
	m.AddRow(6, text.NewCol(12, sub, props.Text{Size: 9, Align: align.Center, Color: gray()}))

	// Engagement summary – who the report is for + the testing window, up front so the
	// deliverable reads as a client report.
	section(m, "Engagement summary")
	m.AddRow(5,
		text.NewCol(6, "Client: "+nonEmpty(eng.Client, "–"), props.Text{Size: 9}),
		text.NewCol(6, "Status: "+nonEmpty(string(eng.Status), "–"), props.Text{Size: 9, Color: gray()}))
	m.AddRow(5,
		text.NewCol(6, "Authorization window: "+authWindow(eng), props.Text{Size: 9, Color: gray()}),
		text.NewCol(6, "Report date: "+at.Format("2006-01-02 15:04 UTC"), props.Text{Size: 9, Color: gray()}))
	m.AddRow(5, text.NewCol(12, "Prepared by Synapse "+version+" – authorized security testing only.", props.Text{Size: 8, Color: gray()}))

	// Split actionable third-party findings from first-party historical advisories
	// Only third-party findings count toward risk posture + remediation.
	thirdParty, historical := splitByClass(findings)
	crit, high := severityOf(thirdParty, "critical"), severityOf(thirdParty, "high")

	// Finding quality – shown BEFORE any vulnerability count so the headline numbers
	// are never misread (a flood of stale first-party advisories is not "criticals").
	section(m, "Finding quality")
	m.AddRow(5,
		text.NewCol(4, fmt.Sprintf("Third-party findings: %d", len(thirdParty)), props.Text{Size: 9, Style: fontstyle.Bold}),
		text.NewCol(4, fmt.Sprintf("First-party historical advisories: %d", len(historical)), props.Text{Size: 9, Color: gray()}),
		text.NewCol(4, fmt.Sprintf("Scan confidence: %s", confidenceWord(insight)), props.Text{Size: 9}))
	if insight.HasScan {
		m.AddRow(5,
			text.NewCol(4, fmt.Sprintf("Raw findings: %d", insight.RawFindings), props.Text{Size: 8, Color: gray()}),
			text.NewCol(4, fmt.Sprintf("Actionable: %d", insight.Actionable), props.Text{Size: 8, Style: fontstyle.Bold}),
			text.NewCol(4, fmt.Sprintf("Background: %d", insight.Background), props.Text{Size: 8, Color: gray()}))
		m.AddRow(5,
			text.NewCol(4, fmt.Sprintf("Production: %d", insight.Production), props.Text{Size: 8, Color: gray()}),
			text.NewCol(4, fmt.Sprintf("Development: %d", insight.Development), props.Text{Size: 8, Color: gray()}),
			text.NewCol(4, fmt.Sprintf("Example/Test: %d", insight.ExampleTest), props.Text{Size: 8, Color: gray()}))
		m.AddRow(5,
			text.NewCol(6, fmt.Sprintf("Version coverage: %.0f%%", insight.VersionCoveragePct), props.Text{Size: 8, Color: gray()}),
			text.NewCol(6, fmt.Sprintf("Dependency-path coverage: %.0f%%", insight.PathCoveragePct), props.Text{Size: 8, Color: gray()}))
		if len(insight.PriorityCounts) > 0 {
			m.AddRow(5,
				text.NewCol(12, "Risk priority – "+priorityLine(insight.PriorityCounts), props.Text{Size: 8, Color: gray()}))
		}
	}

	// Executive summary – posture in one line + third-party headline numbers.
	section(m, "Executive summary")
	m.AddRow(10, text.NewCol(12, executivePosture(crit, high, len(thirdParty), insight), props.Text{Size: 10}))
	m.AddRow(5,
		text.NewCol(4, fmt.Sprintf("Third-party findings: %d", len(thirdParty)), props.Text{Size: 9, Style: fontstyle.Bold}),
		text.NewCol(4, fmt.Sprintf("Critical: %d", crit), props.Text{Size: 9, Style: fontstyle.Bold, Color: sevColor("critical")}),
		text.NewCol(4, fmt.Sprintf("High: %d", high), props.Text{Size: 9, Style: fontstyle.Bold, Color: sevColor("high")}))

	// Top remediation priorities – what to fix first (third-party only).
	if len(thirdParty) > 0 {
		section(m, "Top remediation priorities")
		for i, f := range thirdParty {
			if i >= 5 {
				break
			}
			label := f.Title
			if f.KEV {
				label += "  [KEV]"
			}
			m.AddRow(5,
				text.NewCol(1, fmt.Sprintf("%d.", i+1), props.Text{Size: 9}),
				text.NewCol(2, string(f.Severity), props.Text{Size: 9, Style: fontstyle.Bold, Color: sevColor(f.Severity)}),
				text.NewCol(9, label, props.Text{Size: 9}))
		}
	}

	// Scope.
	section(m, "Scope")
	if len(eng.Scope.InScope) == 0 {
		m.AddRow(5, text.NewCol(12, "  (no in-scope targets recorded)", props.Text{Size: 9, Color: gray()}))
	}
	for _, t := range eng.Scope.InScope {
		m.AddRow(5, text.NewCol(12, "  in   "+string(t.Kind)+"   "+t.Value, props.Text{Size: 9}))
	}
	for _, t := range eng.Scope.OutOfScope {
		m.AddRow(5, text.NewCol(12, "  out  "+string(t.Kind)+"   "+t.Value, props.Text{Size: 9, Color: gray()}))
	}
	m.AddRow(5, text.NewCol(12, "Authorization window: "+authWindow(eng), props.Text{Size: 9, Color: gray()}))

	// Methodology – what was performed + standards + ordering, so a client/auditor can
	// judge coverage. Deterministic static text + scan-derived flags.
	section(m, "Methodology")
	if insight.HasScan {
		m.AddRow(10, text.NewCol(12,
			"Software Composition Analysis: the target was acquired into an isolated workspace (never executed), an SBOM was generated, and components were correlated against vulnerability advisories (OSV + Grype) and de-duplicated per advisory+component+version.",
			props.Text{Size: 8, Color: gray()}))
	} else {
		m.AddRow(6, text.NewCol(12,
			"Findings were recorded manually by the assessment team against the authorized scope.",
			props.Text{Size: 8, Color: gray()}))
	}
	m.AddRow(8, text.NewCol(12,
		"Risk priority orders remediation by CISA KEV first, then EPSS × CVSS – not raw CVSS. Standards: CycloneDX 1.7 + SPDX 3.0, SARIF 2.1, OpenVEX/CSAF, KEV + EPSS. Every artifact is sealed into a per-engagement hash chain.",
		props.Text{Size: 8, Color: gray()}))

	// Severity summary (third-party only).
	section(m, "Third-party findings by severity")
	counts := severityCounts(thirdParty)
	if len(counts) == 0 {
		m.AddRow(5, text.NewCol(12, "No actionable third-party findings at or above the threshold.", props.Text{Size: 9, Color: gray()}))
	}
	for _, c := range counts {
		m.AddRow(5,
			text.NewCol(3, c.sev, props.Text{Size: 9, Style: fontstyle.Bold, Color: sevColor(shared.Severity(c.sev))}),
			text.NewCol(9, fmt.Sprintf("%d", c.n), props.Text{Size: 9}))
	}

	// Detection sources summary – third-party findings only.
	if ds := detectionSummary(thirdParty); ds.total > 0 {
		section(m, "Detection sources")
		m.AddRow(5,
			text.NewCol(6, fmt.Sprintf("Findings with advisories: %d", ds.total), props.Text{Size: 9}),
			text.NewCol(6, fmt.Sprintf("High-confidence (multi-source): %d", ds.highConf), props.Text{Size: 9}))
		m.AddRow(5,
			text.NewCol(4, fmt.Sprintf("Detected by OSV: %d", ds.osv), props.Text{Size: 9, Color: gray()}),
			text.NewCol(4, fmt.Sprintf("Detected by Grype: %d", ds.grype), props.Text{Size: 9, Color: gray()}),
			text.NewCol(4, fmt.Sprintf("Correlated by both: %d", ds.correlated), props.Text{Size: 9, Color: gray()}))
	}

	// Findings detail (third-party, actionable).
	if len(thirdParty) > 0 {
		section(m, "Third-party findings")
		m.AddRow(6,
			text.NewCol(2, "SEVERITY", hdr()),
			text.NewCol(6, "FINDING", hdr()),
			text.NewCol(2, "STATUS", hdr()),
			text.NewCol(2, "RISK", hdr()))
		for _, f := range thirdParty {
			title := f.Title
			if f.KEV {
				title += "  [KEV]"
			}
			m.AddRow(6,
				text.NewCol(2, string(f.Severity), props.Text{Size: 8, Style: fontstyle.Bold, Color: sevColor(f.Severity)}),
				text.NewCol(6, title, props.Text{Size: 8}),
				text.NewCol(2, statusText(f.Status), props.Text{Size: 8}),
				text.NewCol(2, fmt.Sprintf("%.2f", f.RiskScore), props.Text{Size: 8, Align: align.Right}))
		}
	}

	// First-party historical advisories – informational, clearly separated. These
	// are matched against the project's own unversioned modules and cannot be
	// confirmed; they are NOT remediation items.
	if len(historical) > 0 {
		section(m, fmt.Sprintf("First-party historical advisories (%d) – informational, not actionable", len(historical)))
		m.AddRow(6, text.NewCol(12,
			"Matched against the project's own modules (no resolvable version). Shown for completeness; excluded from risk counts.",
			props.Text{Size: 8, Color: gray()}))
		for i, f := range historical {
			if i >= 15 {
				m.AddRow(5, text.NewCol(12, fmt.Sprintf("  … and %d more", len(historical)-15), props.Text{Size: 8, Color: gray()}))
				break
			}
			m.AddRow(5, text.NewCol(12, "  "+f.Title, props.Text{Size: 8, Color: gray()}))
		}
	}

	if insight.HasScan {
		// License summary.
		section(m, "License summary")
		m.AddRow(5,
			text.NewCol(6, fmt.Sprintf("Coverage: %.0f%%", insight.LicensePct), props.Text{Size: 9, Style: fontstyle.Bold}),
			text.NewCol(3, fmt.Sprintf("Detected: %d", insight.LicenseDetected), props.Text{Size: 9, Color: gray()}),
			text.NewCol(3, fmt.Sprintf("Unknown: %d", insight.LicenseUnknown), props.Text{Size: 9, Color: gray()}))

		// Scan completeness + detection confidence.
		section(m, "Scan completeness")
		note := insight.CompletenessNote
		if note == "" {
			note = "Complete – dependency versions resolved with confidence."
		}
		m.AddRow(8, text.NewCol(12, note, props.Text{Size: 9, Color: gray()}))

		// Evidence integrity – the chain-of-custody attestation.
		section(m, "Evidence integrity")
		status := "VERIFIED – evidence chain intact"
		if insight.EvidenceCount == 0 {
			status = "no evidence recorded"
		} else if !insight.EvidenceIntact {
			status = "FAILED – evidence chain broken"
		}
		m.AddRow(5, text.NewCol(12, status, props.Text{Size: 9, Style: fontstyle.Bold}))
		if insight.EvidenceHead != "" {
			m.AddRow(5, text.NewCol(12, "Chain head (sha256): "+insight.EvidenceHead, props.Text{Size: 8, Color: gray()}))
		}
		if insight.EvidenceAttested {
			m.AddRow(5, text.NewCol(12, "Origin attested (ed25519) by key "+insight.EvidenceKeyID+" – proves origin, not just integrity.", props.Text{Size: 8, Color: gray()}))
		}

		// Reproducibility.
		section(m, "Reproducibility")
		m.AddRow(5, text.NewCol(12, fmt.Sprintf("Reproducibility score: %d%%", insight.ReproScore), props.Text{Size: 9, Style: fontstyle.Bold}))
		if len(insight.PinnedInputs) > 0 {
			m.AddRow(5, text.NewCol(12, "Pinned: "+strings.Join(insight.PinnedInputs, ", "), props.Text{Size: 8, Color: gray()}))
		}
		if len(insight.UnpinnedInputs) > 0 {
			m.AddRow(5, text.NewCol(12, "Live (unpinned): "+strings.Join(insight.UnpinnedInputs, ", "), props.Text{Size: 8, Color: gray()}))
		}
		if insight.GrypeDBVersion != "" {
			m.AddRow(5, text.NewCol(12, "Grype DB: "+insight.GrypeDBVersion, props.Text{Size: 8, Color: gray()}))
		}
		m.AddRow(5, text.NewCol(12, "Vuln DB snapshot: "+nonEmpty(insight.VulnDBSnapshot, "–"), props.Text{Size: 8, Color: gray()}))
	}

	// Footer / provenance note.
	section(m, "")
	m.AddRow(10, text.NewCol(12,
		"Templated from stored data – no AI is in the report path. "+
			"Findings are ordered by risk priority (CISA KEV, then EPSS x CVSS). "+
			"The delivered PDF is sealed with a SHA-256 returned at download.",
		props.Text{Size: 7, Align: align.Center, Color: gray()}))

	doc, err := m.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate pdf: %w", err)
	}
	return pinModDate(doc.GetBytes()), nil
}

var (
	creationDateRe = regexp.MustCompile(`/CreationDate \((D:[^)]*)\)`)
	modDateRe      = regexp.MustCompile(`/ModDate \(D:[^)]*\)`)
)

// pinModDate copies the pinned /CreationDate onto /ModDate. maroto v2 only exposes
// WithCreationDate; the underlying gofpdf fills /ModDate with the wall clock, which
// would make the bytes – and thus the SHA-256 seal – non-reproducible from the same
// stored data. Both dates share gofpdf's fixed format, so this is a same-length
// rewrite that keeps the xref byte offsets valid.
func pinModDate(pdf []byte) []byte {
	m := creationDateRe.FindSubmatch(pdf)
	if m == nil {
		return pdf
	}
	return modDateRe.ReplaceAll(pdf, []byte("/ModDate ("+string(m[1])+")"))
}

// section adds vertical space and a bold section header (skipped when empty).
func section(m core.Maroto, title string) {
	m.AddRow(4, text.NewCol(12, "", props.Text{}))
	if title != "" {
		m.AddRow(7, text.NewCol(12, title, props.Text{Size: 12, Style: fontstyle.Bold}))
	}
}

func hdr() props.Text {
	return props.Text{Size: 7, Style: fontstyle.Bold, Color: gray()}
}

func gray() *props.Color { return &props.Color{Red: 110, Green: 116, Blue: 130} }

func sevColor(s shared.Severity) *props.Color {
	switch s {
	case shared.SeverityCritical:
		return &props.Color{Red: 255, Green: 0, Blue: 0}
	case shared.SeverityHigh:
		return &props.Color{Red: 255, Green: 0, Blue: 0}
	case shared.SeverityMedium:
		return &props.Color{Red: 255, Green: 192, Blue: 0}
	case shared.SeverityLow:
		return &props.Color{Red: 0, Green: 176, Blue: 80}
	default:
		return gray()
	}
}

type sevCount struct {
	sev string
	n   int
}

// priorityLine renders the priority distribution deterministically (P1..P5).
func priorityLine(counts map[int]int) string {
	parts := make([]string, 0, 5)
	for p := 1; p <= 5; p++ {
		if n, ok := counts[p]; ok && n > 0 {
			parts = append(parts, fmt.Sprintf("P%d: %d", p, n))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "   ")
}

// splitByClass partitions findings into actionable third-party and first-party
// historical advisories, preserving the (already risk-sorted) order.
func splitByClass(findings []finding.Finding) (thirdParty, historical []finding.Finding) {
	for _, f := range findings {
		if f.Class == finding.ClassFirstPartyHistoric {
			historical = append(historical, f)
		} else {
			thirdParty = append(thirdParty, f)
		}
	}
	return thirdParty, historical
}

// severityOf counts findings of a given severity.
func severityOf(findings []finding.Finding, sev shared.Severity) int {
	n := 0
	for _, f := range findings {
		if f.Severity == sev {
			n++
		}
	}
	return n
}

// executivePosture is the one-line risk verdict for the executive summary.
func executivePosture(crit, high, total int, insight ports.ReportInsight) string {
	switch {
	case crit > 0:
		return fmt.Sprintf("This project is at HIGH RISK: %d critical and %d high-severity findings require prompt remediation.", crit, high)
	case high > 0:
		return fmt.Sprintf("This project has ELEVATED RISK: %d high-severity findings should be remediated.", high)
	case total > 0:
		return fmt.Sprintf("This project has LOW RISK: %d findings, none critical or high.", total)
	case insight.HasScan && !insight.Confident:
		return "No findings, but the scan was INCOMPLETE – treat the result as indicative, not conclusive."
	default:
		return "No findings at or above the promotion threshold were identified."
	}
}

func confidenceWord(insight ports.ReportInsight) string {
	if !insight.HasScan {
		return "n/a"
	}
	if insight.Confident {
		return "high"
	}
	return "partial"
}

type detSummary struct{ total, osv, grype, correlated, highConf int }

// detectionSummary tallies which sources detected each finding + confidence, for
// the report's Detection sources section (deterministic; counts only).
func detectionSummary(findings []finding.Finding) detSummary {
	var s detSummary
	for _, f := range findings {
		if len(f.Sources) == 0 {
			continue
		}
		s.total++
		osv, grype := false, false
		for _, src := range f.Sources {
			switch src {
			case "osv":
				osv = true
			case "grype":
				grype = true
			}
		}
		if osv {
			s.osv++
		}
		if grype {
			s.grype++
		}
		if osv && grype {
			s.correlated++
		}
		if f.Confidence == "high" || f.Confidence == "very_high" {
			s.highConf++
		}
	}
	return s
}

// severityCounts returns the non-zero severity tallies in fixed display order
// (deterministic – never map iteration order). Any non-standard severity is
// bucketed as unknown.
func severityCounts(findings []finding.Finding) []sevCount {
	order := []shared.Severity{
		shared.SeverityCritical, shared.SeverityHigh, shared.SeverityMedium,
		shared.SeverityLow, shared.SeverityInfo, shared.SeverityUnknown,
	}
	n := map[shared.Severity]int{}
	for _, f := range findings {
		switch f.Severity {
		case shared.SeverityCritical, shared.SeverityHigh, shared.SeverityMedium, shared.SeverityLow, shared.SeverityInfo:
			n[f.Severity]++
		default:
			n[shared.SeverityUnknown]++
		}
	}
	out := make([]sevCount, 0, len(order))
	for _, s := range order {
		if n[s] > 0 {
			out = append(out, sevCount{string(s), n[s]})
		}
	}
	return out
}

func statusText(s finding.Status) string {
	if s == "" {
		return "open"
	}
	out := []rune(string(s))
	for i, r := range out {
		if r == '_' {
			out[i] = ' '
		}
	}
	return string(out)
}

func authWindow(eng *engagement.Engagement) string {
	const layout = "2006-01-02"
	from, to := "open", "open"
	if eng.AuthorizedFrom != nil {
		from = eng.AuthorizedFrom.UTC().Format(layout)
	}
	if eng.AuthorizedTo != nil {
		to = eng.AuthorizedTo.UTC().Format(layout)
	}
	return from + " → " + to
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
