// Package report generates an engagement's report from stored data and seals it
// with a SHA-256 (chain-of-custody). No LLM is in the report path:
// every format is a pure, deterministic function of the stored findings. PDF is
// rendered by the maroto renderer; HTML/DOCX are assembled into a format-agnostic
// ReportDocument here and handed to a DocRenderer.
package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/compliance"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Section keys the report builder can select/order. The canonical order below is
// also the default when a request names no sections. The leading sections
// (engagement → scope → methodology → summary → risk → top) make the output a
// client-ready deliverable, not just a findings dump.
const (
	SectionEngagement  = "engagement"  // engagement summary (client, dates, prepared-by)
	SectionScope       = "scope"       // scope statement + authorization window
	SectionMethodology = "methodology" // what was performed + standards + ordering
	SectionSummary     = "summary"     // executive summary (narrative posture)
	SectionRemediation = "remediation" // retest / remediation status (retest reports)
	SectionRisk        = "risk"        // risk overview (severity + priority breakdown)
	SectionTop         = "top"         // top findings to remediate first
	SectionFindings    = "findings"    // full findings table
	SectionDetails     = "details"     // per-finding detail
	SectionScan        = "scan"        // scan & SBOM insight
	SectionEvidence    = "evidence"    // evidence & chain of custody
	SectionExhibits    = "exhibits"    // inline evidence images (captured screenshots)
)

// sectionOrder is the canonical render order; selection is always rendered in this
// order regardless of the order requested, so the output stays deterministic.
var sectionOrder = []string{
	SectionEngagement, SectionScope, SectionMethodology, SectionSummary,
	SectionRemediation, SectionRisk, SectionTop, SectionFindings, SectionDetails, SectionScan, SectionEvidence, SectionExhibits,
}

// Report types frame the deliverable: each picks a title, an
// executive-summary posture line, a methodology narrative, and a default section set.
// The underlying finding data is identical – only the framing + selection differ, so
// nothing is invented. TypeRetest additionally surfaces real retest
// verdicts in a Remediation Status section.
const (
	TypeSCA      = "sca"      // dependency / SCA report (the default, current behavior)
	TypeExternal = "external" // external / perimeter assessment
	TypeInternal = "internal" // internal network assessment
	TypeRetest   = "retest"   // remediation verification (retest) report
)

// reportProfile is the per-type framing. Empty title falls back to the engagement
// name; sections is the default section set when a request names none.
type reportProfile struct {
	title       string
	posture     string   // leading line in the executive summary
	methodology []string // methodology narrative (the common standards lines are appended)
	sections    []string // default section selection + order for this type
}

// fullSections is the SCA/default section set. The retest-only remediation section
// and the exhibits section appear only when their data exists (retest verdicts /
// captured images), so including them here is safe – they self-omit otherwise.
var fullSections = []string{
	SectionEngagement, SectionScope, SectionMethodology, SectionSummary,
	SectionRisk, SectionTop, SectionFindings, SectionDetails, SectionScan, SectionEvidence, SectionExhibits,
}

// assessmentSections is the external/internal pentest set: same client-ready spine,
// minus the SCA-specific scan section, plus chain-of-custody evidence + image exhibits.
var assessmentSections = []string{
	SectionEngagement, SectionScope, SectionMethodology, SectionSummary,
	SectionRisk, SectionTop, SectionFindings, SectionDetails, SectionEvidence, SectionExhibits,
}

var reportProfiles = map[string]reportProfile{
	TypeSCA: {
		title:    "",
		sections: fullSections,
	},
	TypeExternal: {
		title:   "External Security Assessment",
		posture: "This report presents the results of an authorized EXTERNAL assessment of the client's internet-facing attack surface within the stated scope.",
		methodology: []string{
			"External assessment: testing was conducted from an external (internet) vantage against the in-scope perimeter – reconnaissance of exposed assets, identification of externally-reachable services, and analysis of the resulting findings. No internal network position was assumed.",
		},
		sections: assessmentSections,
	},
	TypeInternal: {
		title:   "Internal Network Assessment",
		posture: "This report presents the results of an authorized INTERNAL assessment conducted from a position inside the client's network within the stated scope.",
		methodology: []string{
			"Internal assessment: testing was conducted from an authenticated/internal network position against the in-scope assets – enumeration of internal services and exposure, and analysis of the resulting findings. The starting position reflects an assumed-breach or insider scenario as agreed in scope.",
		},
		sections: assessmentSections,
	},
	TypeRetest: {
		title:   "Remediation Retest Report",
		posture: "This report verifies remediation of previously-reported findings; each finding's current retest verdict is summarized below.",
		methodology: []string{
			"Retest: each previously-reported finding was re-tested to confirm whether the underlying issue has been remediated. Verdicts are remediated (fix confirmed), still vulnerable (issue reproduced), or not reproducible (could not be confirmed). No new findings are introduced by a retest.",
		},
		sections: []string{
			SectionEngagement, SectionScope, SectionSummary, SectionRemediation,
			SectionRisk, SectionFindings, SectionEvidence, SectionExhibits,
		},
	},
}

// profileFor returns the profile for a type, defaulting to the SCA profile for an
// unknown type. Callers must enforce ValidType first (Render does) so an unknown type
// is rejected rather than silently rendered as SCA.
func profileFor(t string) reportProfile {
	if p, ok := reportProfiles[t]; ok {
		return p
	}
	return reportProfiles[TypeSCA]
}

// ValidType reports whether t is a known report type (empty = the default SCA type).
func ValidType(t string) bool {
	if t == "" {
		return true
	}
	_, ok := reportProfiles[t]
	return ok
}

// Format identifiers for the document renderers (PDF has its own typed path).
const (
	FormatHTML = "html"
	FormatDOCX = "docx"
)

// Options customizes a built report (the "report builder"). Zero value = the full
// report in every section, no status filter. It only narrows/relabels stored data;
// it never adds anything not derived from the engagement.
type Options struct {
	Format   string   // html | docx
	Type     string   // sca | external | internal | retest; empty = sca
	Statuses []string // include only findings in these statuses; empty = all
	Sections []string // include only these section keys; empty = the type's default set
	Title    string   // override the report title; empty = the type's default / engagement name
}

// Exhibit caps bound report size deterministically (first-N in chain order, never
// random): a per-image byte cap, a count cap, and a TOTAL byte budget so a tenant who
// captures many large screenshots into their own engagement cannot blow up report
// memory (50 × 5 MiB would otherwise be ~250 MiB raw + base64 expansion per render).
const (
	maxExhibitImages     = 50
	maxExhibitBytes      = 5 << 20   // 5 MiB per image
	maxExhibitTotalBytes = 128 << 20 // 128 MiB of embedded image bytes per report
)

// Service builds engagement reports in multiple formats.
type Service struct {
	engagements  ports.EngagementRepository
	findings     ports.FindingRepository
	retests      ports.RetestRepository       // optional; nil disables the retest/remediation section
	evidence     ports.ReportEvidenceProvider // optional; nil disables the image-exhibits section
	renderer     ports.ReportRenderer
	insight      ports.ReportInsightProvider
	clock        ports.Clock
	version      string
	docRenderers map[string]ports.DocRenderer
}

// NewService wires the report service. insight/retests/evidence may each be nil – the
// report then omits the corresponding sections (scan-level executive sections, the
// retest remediation status, and the evidence image exhibits respectively).
func NewService(e ports.EngagementRepository, f ports.FindingRepository, retests ports.RetestRepository, evidence ports.ReportEvidenceProvider, r ports.ReportRenderer, insight ports.ReportInsightProvider, clock ports.Clock, version string) *Service {
	return &Service{engagements: e, findings: f, retests: retests, evidence: evidence, renderer: r, insight: insight, clock: clock, version: version, docRenderers: map[string]ports.DocRenderer{}}
}

// RegisterFormat registers a DocRenderer for a format key (e.g. "html", "docx").
// Wired in the composition root, once per format, before the server starts serving
// (it mutates the renderer map and is not safe to call concurrently with Render).
func (s *Service) RegisterFormat(format string, r ports.DocRenderer) {
	if s.docRenderers == nil {
		s.docRenderers = map[string]ports.DocRenderer{}
	}
	s.docRenderers[format] = r
}

// loaded is the stored data a report is built from, plus the pinned timestamp.
type loaded struct {
	eng         *engagement.Engagement
	findings    []finding.Finding
	insight     ports.ReportInsight
	retests     map[shared.ID][]finding.Retest // per-finding retest history (retest reports only)
	images      []ports.ReportImage            // evidence image exhibits (when the exhibits section is wanted)
	generatedAt time.Time
}

// load reads the engagement + findings + scan insight, enforces the chain-of-custody
// gate, and pins the report timestamp – the shared front half of every format.
func (s *Service) load(ctx context.Context, tenantID, engagementID shared.ID) (loaded, error) {
	eng, err := s.engagements.GetByIDInTenant(ctx, tenantID, engagementID)
	if err != nil {
		return loaded{}, fmt.Errorf("load engagement: %w", err)
	}
	// Publishability gate: read through the single repository path
	// (ListPublishableByEngagement) that SARIF, OpenVEX, and the engagement bundle also
	// use, so EVERY report format (PDF via Generate, HTML/DOCX via Render) shares one
	// enforced gate and no surface can leak an unproven exploitation finding.
	findings, err := s.findings.ListPublishableByEngagement(ctx, engagementID)
	if err != nil {
		return loaded{}, fmt.Errorf("load findings: %w", err)
	}
	var insight ports.ReportInsight
	if s.insight != nil {
		insight, err = s.insight.ReportInsight(ctx, engagementID)
		if err != nil {
			return loaded{}, fmt.Errorf("load report insight: %w", err)
		}
		// Chain-of-custody: a tampered evidence ledger blocks the report regardless of
		// whether a scan ran – recon-only/manual engagements seal evidence too, and the
		// insight provider fails closed if it cannot verify the chain.
		if insight.EvidenceCount > 0 && !insight.EvidenceIntact {
			return loaded{}, fmt.Errorf("%w: evidence chain verification failed – report blocked", shared.ErrValidation)
		}
	}
	// Pin the report timestamp to the SCAN time (not generation time) so output is a
	// pure function of stored data – byte-identical + SHA-256-stable across repeated
	// generations (determinism fix). Fall back to Now only with no scan.
	generatedAt := s.clock.Now()
	if insight.HasScan && !insight.ScanTime.IsZero() {
		generatedAt = insight.ScanTime
	}
	return loaded{eng: eng, findings: findings, insight: insight, generatedAt: generatedAt}, nil
}

// Generate renders the engagement's PDF report from stored data and returns the
// PDF bytes plus the lowercase hex SHA-256 of those bytes (the integrity seal).
// l.findings is promotable-gated by load(), so an unproven finding never reaches the PDF.
func (s *Service) Generate(ctx context.Context, tenantID, engagementID shared.ID) ([]byte, string, error) {
	l, err := s.load(ctx, tenantID, engagementID)
	if err != nil {
		return nil, "", err
	}
	pdf, err := s.renderer.Render(ctx, l.eng, l.findings, l.insight, l.generatedAt, s.version)
	if err != nil {
		return nil, "", fmt.Errorf("render report: %w", err)
	}
	sum := sha256.Sum256(pdf)
	return pdf, hex.EncodeToString(sum[:]), nil
}

// Render builds a customized report in opts.Format (html|docx) from stored data and
// returns the bytes, MIME content-type, and the hex SHA-256 seal. The document is
// assembled deterministically here; the DocRenderer only formats it (no business
// logic, no LLM). Filename/Content-Disposition is the adapter's concern.
func (s *Service) Render(ctx context.Context, tenantID, engagementID shared.ID, opts Options) (data []byte, contentType, sha string, err error) {
	rnd := s.docRenderers[opts.Format]
	if rnd == nil {
		return nil, "", "", fmt.Errorf("%w: unsupported report format %q", shared.ErrValidation, opts.Format)
	}
	if !ValidType(opts.Type) {
		return nil, "", "", fmt.Errorf("%w: unknown report type %q", shared.ErrValidation, opts.Type)
	}
	l, err := s.load(ctx, tenantID, engagementID)
	if err != nil {
		return nil, "", "", err
	}
	// Resolve the section set once so we only fetch what the report will show.
	want := sectionSet(opts.Sections, profileFor(opts.Type).sections)
	// A retest report surfaces real retest verdicts – fetch them only for that type so
	// the other reports cost no extra queries.
	if opts.Type == TypeRetest && s.retests != nil {
		l.retests, err = s.loadRetests(ctx, engagementID, l.findings)
		if err != nil {
			return nil, "", "", err
		}
	}
	// Evidence image exhibits: fetch the captured screenshots only when the section is
	// included and a provider is configured.
	if want[SectionExhibits] && s.evidence != nil {
		l.images, err = s.loadExhibits(ctx, engagementID)
		if err != nil {
			return nil, "", "", err
		}
	}
	doc := s.buildDocument(l, opts)
	data, err = rnd.Render(ctx, doc)
	if err != nil {
		return nil, "", "", fmt.Errorf("render %s report: %w", opts.Format, err)
	}
	sum := sha256.Sum256(data)
	return data, contentTypeFor(opts.Format), hex.EncodeToString(sum[:]), nil
}

func contentTypeFor(format string) string {
	switch format {
	case FormatDOCX:
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	default: // html
		return "text/html; charset=utf-8"
	}
}

// buildDocument assembles the format-agnostic report from the loaded data + options.
func (s *Service) buildDocument(l loaded, opts Options) ports.ReportDocument {
	// l.findings is already publishability-gated by load() (via ListPublishableByEngagement),
	// so it holds only promotable findings for every format. Here we only
	// apply the optional status filter on top of that gate.
	findings := filterByStatus(l.findings, opts.Statuses)
	profile := profileFor(opts.Type)

	title := strings.TrimSpace(opts.Title)
	if title == "" {
		title = nonEmpty(profile.title, nonEmpty(l.eng.Name, "Security Assessment Report"))
	}
	at := l.generatedAt.UTC()
	subtitle := "Generated " + at.Format("2006-01-02 15:04 UTC") + "  ·  Synapse " + s.version
	if l.eng.Client != "" {
		subtitle = "Client: " + l.eng.Client + "  ·  " + subtitle
	}

	// An explicit section request wins; otherwise use the type's default set.
	want := sectionSet(opts.Sections, profile.sections)
	var sections []ports.ReportSection
	for _, key := range sectionOrder {
		if !want[key] {
			continue
		}
		var sec ports.ReportSection
		var ok bool
		switch key {
		case SectionEngagement:
			sec, ok = engagementSection(l.eng, l.insight, at, s.version)
		case SectionScope:
			sec, ok = scopeSection(l.eng)
		case SectionMethodology:
			sec, ok = methodologySection(profile, l.insight)
		case SectionSummary:
			sec, ok = summarySection(profile, findings, l.insight)
		case SectionRemediation:
			sec, ok = remediationSection(findings, l.retests)
		case SectionRisk:
			sec, ok = riskOverviewSection(findings)
		case SectionTop:
			sec, ok = topFindingsSection(findings)
		case SectionFindings:
			sec, ok = findingsSection(findings)
		case SectionDetails:
			sec, ok = detailsSection(findings)
		case SectionScan:
			sec, ok = scanSection(l.insight)
		case SectionEvidence:
			sec, ok = evidenceSection(l.insight)
		case SectionExhibits:
			sec, ok = exhibitsSection(l.images)
		}
		if ok {
			sections = append(sections, sec)
		}
	}

	return ports.ReportDocument{
		Title:       title,
		Subtitle:    subtitle,
		GeneratedAt: at,
		Version:     s.version,
		Sections:    sections,
	}
}

// loadRetests fetches the per-finding retest history for the engagement, keyed by
// finding id, preserving the repository's append order (deterministic output).
func (s *Service) loadRetests(ctx context.Context, engagementID shared.ID, findings []finding.Finding) (map[shared.ID][]finding.Retest, error) {
	out := make(map[shared.ID][]finding.Retest, len(findings))
	for _, f := range findings {
		rs, err := s.retests.ListByEngagementFinding(ctx, engagementID, f.ID)
		if err != nil {
			return nil, fmt.Errorf("load retests for %s: %w", f.ID, err)
		}
		if len(rs) > 0 {
			out[f.ID] = rs
		}
	}
	return out, nil
}

// loadExhibits fetches the engagement's captured image artifacts (chain order) and
// returns the raster ones as report images, bounded by the deterministic caps. Each
// exhibit's bytes are re-verified against its sha by the vault read path; non-image or
// oversized artifacts are skipped. A purely additive section – never fails the report.
func (s *Service) loadExhibits(ctx context.Context, engagementID shared.ID) ([]ports.ReportImage, error) {
	arts, err := s.evidence.ListArtifacts(ctx, engagementID)
	if err != nil {
		return nil, fmt.Errorf("list evidence artifacts: %w", err)
	}
	var images []ports.ReportImage
	total := 0
	for _, a := range arts {
		if len(images) >= maxExhibitImages {
			break
		}
		if a.Size > maxExhibitBytes {
			continue
		}
		data, err := s.evidence.ArtifactBytes(ctx, engagementID, a.SHA256)
		if err != nil {
			continue // a tampered/missing blob is skipped, not fatal to the report
		}
		if len(data) > maxExhibitBytes {
			continue
		}
		if total+len(data) > maxExhibitTotalBytes {
			break // total budget reached – stop adding (deterministic: first-N in order)
		}
		mime, ok := rasterMIME(data)
		if !ok {
			continue // only embed raster images (no SVG/HTML/other)
		}
		total += len(data)
		images = append(images, ports.ReportImage{
			Caption: exhibitCaption(a),
			MIME:    mime,
			Data:    data,
			SHA256:  a.SHA256,
		})
	}
	return images, nil
}

// rasterMIME reports the image MIME if data is an allowed raster format. SVG is
// deliberately excluded (it can carry script and must never be embedded as a data
// URI). http.DetectContentType returns image/png|jpeg|gif for these; SVG sniffs as
// text/xml and is rejected.
func rasterMIME(data []byte) (string, bool) {
	switch http.DetectContentType(data) {
	case "image/png":
		return "image/png", true
	case "image/jpeg":
		return "image/jpeg", true
	case "image/gif":
		return "image/gif", true
	default:
		return "", false
	}
}

// exhibitCaption builds a human caption for an exhibit, ending with the short sha so a
// reader can tie it back to the evidence chain.
func exhibitCaption(a ports.EvidenceArtifact) string {
	label := nonEmpty(a.Filename, nonEmpty(a.Note, a.Kind))
	if label == "" {
		label = "Evidence artifact"
	}
	short := a.SHA256
	if len(short) > 12 {
		short = short[:12]
	}
	return label + "  ·  sha256 " + short
}

// exhibitsSection renders the captured image exhibits as a gallery. Each image is
// captioned with its source + chain sha (so it is verifiable against the ledger).
// Omitted when there are no embeddable images.
func exhibitsSection(images []ports.ReportImage) (ports.ReportSection, bool) {
	if len(images) == 0 {
		return ports.ReportSection{}, false
	}
	return ports.ReportSection{
		Heading:    "Evidence Exhibits",
		Paragraphs: []string{"Captured evidence below. Each exhibit carries the SHA-256 under which it is sealed in the engagement's evidence chain, so it can be verified against the ledger."},
		Images:     images,
	}, true
}

// sectionSet returns the set of section keys to include. An empty selection falls
// back to defaults (the type's default set); unknown keys are ignored.
func sectionSet(selected, defaults []string) map[string]bool {
	keys := selected
	if len(keys) == 0 {
		keys = defaults
	}
	out := make(map[string]bool, len(keys))
	for _, k := range keys {
		out[strings.TrimSpace(strings.ToLower(k))] = true
	}
	return out
}

// filterByStatus keeps only findings whose status is in statuses (empty = all).
func filterByStatus(findings []finding.Finding, statuses []string) []finding.Finding {
	if len(statuses) == 0 {
		return findings
	}
	keep := map[string]bool{}
	for _, st := range statuses {
		keep[strings.TrimSpace(strings.ToLower(st))] = true
	}
	out := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		if keep[strings.ToLower(string(f.Status))] {
			out = append(out, f)
		}
	}
	return out
}

// engagementSection is the deliverable's front matter: who it is for, when it was
// produced, and by what. Always present (built purely from stored engagement data).
func engagementSection(eng *engagement.Engagement, insight ports.ReportInsight, at time.Time, version string) (ports.ReportSection, bool) {
	tbl := &ports.ReportTable{Headers: []string{"Field", "Value"}}
	row := func(k, v string) { tbl.Rows = append(tbl.Rows, []string{k, nonEmpty(v, "–")}) }
	row("Engagement", eng.Name)
	row("Client", eng.Client)
	row("Status", titleCase(string(eng.Status)))
	row("Authorization window", authorizationWindow(eng))
	if insight.HasScan && insight.ScanTarget != "" {
		row("Primary target", insight.ScanTarget)
	}
	row("Report date", at.Format("2006-01-02 15:04 UTC"))
	row("Prepared by", "Synapse "+version)
	sec := ports.ReportSection{
		Heading: "Engagement Summary",
		Paragraphs: []string{
			"This report documents the results of an authorized security assessment conducted under the scope and authorization window stated below. It is intended for the named client and their designated recipients.",
		},
		Table: tbl,
	}
	return sec, true
}

// scopeSection states exactly what was authorized for testing – the legal + technical
// boundary of the engagement. Always present.
func scopeSection(eng *engagement.Engagement) (ports.ReportSection, bool) {
	sec := ports.ReportSection{Heading: "Scope Statement"}
	sec.Paragraphs = append(sec.Paragraphs,
		"Testing was authorized only against the in-scope targets listed below, within the stated authorization window. Out-of-scope assets were excluded by policy.")
	tbl := &ports.ReportTable{Headers: []string{"Disposition", "Type", "Target"}}
	for _, t := range eng.Scope.InScope {
		tbl.Rows = append(tbl.Rows, []string{"In scope", string(t.Kind), t.Value})
	}
	for _, t := range eng.Scope.OutOfScope {
		tbl.Rows = append(tbl.Rows, []string{"Out of scope", string(t.Kind), t.Value})
	}
	if len(tbl.Rows) == 0 {
		sec.Paragraphs = append(sec.Paragraphs, "No explicit scope targets were recorded for this engagement.")
	} else {
		sec.Table = tbl
	}
	sec.Paragraphs = append(sec.Paragraphs, "Authorization window: "+authorizationWindow(eng)+".")
	return sec, true
}

// methodologySection describes what was performed and to which standards – so a
// client (or an auditor) can judge coverage. Deterministic, derived from the scan
// insight; no narrative is invented.
func methodologySection(profile reportProfile, insight ports.ReportInsight) (ports.ReportSection, bool) {
	sec := ports.ReportSection{Heading: "Methodology"}
	// A typed report leads with its own methodology narrative; the SCA/default report
	// derives the narrative from whether a scan ran.
	if len(profile.methodology) > 0 {
		sec.Paragraphs = append(sec.Paragraphs, profile.methodology...)
	} else if insight.HasScan {
		sec.Paragraphs = append(sec.Paragraphs,
			"Software Composition Analysis (SCA): the target's source was acquired into an isolated workspace (never executed), an SBOM was generated, and its components were correlated against vulnerability advisories. Findings are de-duplicated per advisory+component+version.")
		sec.Paragraphs = append(sec.Paragraphs,
			"Detection sources were correlated (OSV and Grype); a finding confirmed by more than one source is treated as higher confidence.")
	} else {
		sec.Paragraphs = append(sec.Paragraphs,
			"Findings in this report were recorded manually by the assessment team against the authorized scope.")
	}
	sec.Paragraphs = append(sec.Paragraphs,
		"Risk priority orders remediation by CISA KEV (known exploited) first, then EPSS exploitation probability weighted by CVSS – not by raw CVSS alone.")
	sec.Paragraphs = append(sec.Paragraphs,
		"Standards: CycloneDX 1.7 and SPDX 3.0 (SBOM), SARIF 2.1 (findings), OpenVEX/CSAF (exploitability), CISA KEV and FIRST EPSS (prioritization).")
	sec.Paragraphs = append(sec.Paragraphs,
		"Every recorded artifact is sealed into a per-engagement hash chain (chain of custody); this report is templated from that stored data with no AI in the report path.")
	return sec, true
}

// remediationSection summarizes the latest retest verdict per finding (retest
// reports). Built from real retest history; omitted when there is none. The latest
// retest per finding is the last record (append order), so the verdict reflects the
// most recent re-test.
func remediationSection(findings []finding.Finding, retests map[shared.ID][]finding.Retest) (ports.ReportSection, bool) {
	if len(retests) == 0 {
		return ports.ReportSection{}, false
	}
	tbl := &ports.ReportTable{Headers: []string{"ID", "Finding", "Severity", "Retest verdict", "Re-tested"}}
	var remediated, stillVuln, notRepro, retested int
	for _, f := range findings {
		rs := retests[f.ID]
		if len(rs) == 0 {
			continue
		}
		// The latest retest (append-order: oldest-first) is the current verdict. Tester
		// and Note are intentionally omitted from this client deliverable – Note is
		// free-form operator text and the verdict + date are what the customer needs.
		latest := rs[len(rs)-1]
		retested++
		switch latest.Outcome {
		case finding.RetestRemediated:
			remediated++
		case finding.RetestStillVulnerable:
			stillVuln++
		case finding.RetestNotReproducible:
			notRepro++
		}
		tbl.Rows = append(tbl.Rows, []string{
			string(f.ID),
			nonEmpty(f.Title, "Untitled finding"),
			titleCase(string(f.Severity)),
			retestVerdictLabel(latest.Outcome),
			latest.At.UTC().Format("2006-01-02"),
		})
	}
	if retested == 0 {
		return ports.ReportSection{}, false
	}
	sec := ports.ReportSection{
		Heading: "Remediation Status",
		Paragraphs: []string{
			fmt.Sprintf("Of %d re-tested finding(s): %d remediated, %d still vulnerable, %d not reproducible.", retested, remediated, stillVuln, notRepro),
		},
		Table: tbl,
	}
	if stillVuln > 0 {
		sec.Paragraphs = append(sec.Paragraphs, fmt.Sprintf("%d finding(s) remain exploitable and require further remediation.", stillVuln))
	}
	return sec, true
}

// retestVerdictLabel renders a retest outcome as report-friendly text.
func retestVerdictLabel(o finding.RetestOutcome) string {
	switch o {
	case finding.RetestRemediated:
		return "Remediated"
	case finding.RetestStillVulnerable:
		return "Still vulnerable"
	case finding.RetestNotReproducible:
		return "Not reproducible"
	default:
		return titleCase(strings.ReplaceAll(string(o), "_", " "))
	}
}

// summarySection is the narrative executive summary (posture in prose + headline
// numbers). The severity table lives in the Risk Overview so narrative and data are
// not conflated.
func summarySection(profile reportProfile, findings []finding.Finding, insight ports.ReportInsight) (ports.ReportSection, bool) {
	sec := ports.ReportSection{Heading: "Executive Summary"}
	if profile.posture != "" {
		sec.Paragraphs = append(sec.Paragraphs, profile.posture)
	}
	sec.Paragraphs = append(sec.Paragraphs, executivePosture(findings, insight))
	sec.Paragraphs = append(sec.Paragraphs, fmt.Sprintf("This report covers %d finding(s) for the engagement.", len(findings)))
	if insight.HasScan {
		conf := "preliminary"
		if insight.Confident {
			conf = "confident"
		}
		sec.Paragraphs = append(sec.Paragraphs, fmt.Sprintf("Actionable third-party findings: %d of %d raw (analysis confidence: %s).", insight.Actionable, insight.RawFindings, conf))
		sec.Paragraphs = append(sec.Paragraphs, fmt.Sprintf("Coverage – version: %.0f%%, path: %.0f%%; license detection: %.0f%%.", insight.VersionCoveragePct, insight.PathCoveragePct, insight.LicensePct))
	}
	return sec, true
}

// riskOverviewSection is the severity breakdown table plus the priority distribution
// and the count of known-exploited (KEV) findings. Always present.
func riskOverviewSection(findings []finding.Finding) (ports.ReportSection, bool) {
	sec := ports.ReportSection{Heading: "Risk Overview"}
	counts := severityCounts(findings)
	tbl := &ports.ReportTable{Headers: []string{"Severity", "Count"}}
	for _, sev := range severityOrder {
		tbl.Rows = append(tbl.Rows, []string{titleCase(string(sev)), fmt.Sprintf("%d", counts[sev])})
	}
	sec.Table = tbl
	kev := 0
	for _, f := range findings {
		if f.KEV {
			kev++
		}
	}
	if kev > 0 {
		sec.Paragraphs = append(sec.Paragraphs, fmt.Sprintf("%d finding(s) are on the CISA Known Exploited Vulnerabilities catalog and should be prioritized.", kev))
	}
	if line := priorityDistribution(findings); line != "" {
		sec.Paragraphs = append(sec.Paragraphs, "Risk-priority distribution – "+line+".")
	}
	return sec, true
}

// topFindingsSection lists the highest-priority findings to remediate first. Findings
// arrive already ordered by risk priority, so the first N are the top N.
func topFindingsSection(findings []finding.Finding) (ports.ReportSection, bool) {
	if len(findings) == 0 {
		return ports.ReportSection{}, false
	}
	const topN = 5
	tbl := &ports.ReportTable{Headers: []string{"#", "Severity", "Finding", "Priority", "KEV"}}
	for i, f := range findings {
		if i >= topN {
			break
		}
		kev := "–"
		if f.KEV {
			kev = "yes"
		}
		tbl.Rows = append(tbl.Rows, []string{
			fmt.Sprintf("%d", i+1),
			titleCase(string(f.Severity)),
			nonEmpty(f.Title, "Untitled finding"),
			fmt.Sprintf("%d", f.Priority),
			kev,
		})
	}
	return ports.ReportSection{
		Heading:    "Top Findings",
		Paragraphs: []string{"The findings below are ordered by risk priority (CISA KEV, then EPSS × CVSS) – address them first."},
		Table:      tbl,
	}, true
}

func findingsSection(findings []finding.Finding) (ports.ReportSection, bool) {
	if len(findings) == 0 {
		return ports.ReportSection{Heading: "Findings Overview", Paragraphs: []string{"No findings match the selected filters."}}, true
	}
	tbl := &ports.ReportTable{Headers: []string{"ID", "Title", "Severity", "Status", "CWE", "Priority"}}
	for _, f := range findings {
		tbl.Rows = append(tbl.Rows, []string{
			string(f.ID),
			f.Title,
			titleCase(string(f.Severity)),
			titleCase(strings.ReplaceAll(string(f.Status), "_", " ")),
			f.CWE,
			fmt.Sprintf("%d", f.Priority),
		})
	}
	return ports.ReportSection{Heading: "Findings Overview", Table: tbl}, true
}

func detailsSection(findings []finding.Finding) (ports.ReportSection, bool) {
	if len(findings) == 0 {
		return ports.ReportSection{}, false
	}
	sec := ports.ReportSection{Heading: "Finding Details"}
	for _, f := range findings {
		head := fmt.Sprintf("%s – %s  [%s · %s]", string(f.ID), nonEmpty(f.Title, "Untitled finding"), titleCase(string(f.Severity)), titleCase(strings.ReplaceAll(string(f.Status), "_", " ")))
		sec.Paragraphs = append(sec.Paragraphs, head)
		if d := strings.TrimSpace(f.Description); d != "" {
			sec.Paragraphs = append(sec.Paragraphs, d)
		}
		meta := []string{}
		if f.CWE != "" {
			meta = append(meta, "CWE: "+f.CWE)
		}
		if cl := complianceLabel(f.CWE); cl != "" {
			meta = append(meta, "Compliance: "+cl)
		}
		if f.CVSSVector != "" {
			meta = append(meta, "CVSS: "+f.CVSSVector)
		}
		meta = append(meta, fmt.Sprintf("Risk priority: %d", f.Priority))
		if f.KEV {
			meta = append(meta, "CISA KEV: yes")
		}
		// Coarse JVM class-reachability: flag an unreferenced component (deprioritized, not
		// suppressed) so a reviewer sees the dep the app never statically references.
		if f.ClassReachability == sbom.ReachabilityUnreferenced {
			meta = append(meta, "Reachability: unreferenced (no static reference from app code)")
		}
		sec.Paragraphs = append(sec.Paragraphs, strings.Join(meta, "  ·  "))
	}
	return sec, true
}

// complianceLabel maps a finding's CWE to its compliance controls as a compact "Framework ID" list
// (e.g. "ISO-27001-2022 A.8.28, OWASP-2021 A03:2021, PCI-DSS-4.0 6.2.4"), or "" if the CWE is empty or
// maps to none. It is a pure curated-table lookup (no LLM, deterministic order), so the report path stays
// templated and auditable – a compliance tag is a stored-data lookup, not a model output.
func complianceLabel(cwe string) string {
	controls := compliance.ControlsFor(cwe)
	if len(controls) == 0 {
		return ""
	}
	labels := make([]string, len(controls))
	for i, c := range controls {
		labels[i] = c.Framework + " " + c.ID
	}
	return strings.Join(labels, ", ")
}

func scanSection(insight ports.ReportInsight) (ports.ReportSection, bool) {
	if !insight.HasScan {
		return ports.ReportSection{}, false
	}
	sec := ports.ReportSection{Heading: "Scan & SBOM Insight"}
	if insight.CompletenessNote != "" {
		sec.Paragraphs = append(sec.Paragraphs, insight.CompletenessNote)
	}
	sec.Paragraphs = append(sec.Paragraphs, fmt.Sprintf("Reproducibility score: %d/100.", insight.ReproScore))
	if insight.VulnDBSnapshot != "" {
		sec.Paragraphs = append(sec.Paragraphs, "Vulnerability DB snapshot: "+insight.VulnDBSnapshot)
	}
	if insight.GrypeDBVersion != "" {
		sec.Paragraphs = append(sec.Paragraphs, "Grype DB version: "+insight.GrypeDBVersion)
	}
	sec.Paragraphs = append(sec.Paragraphs, fmt.Sprintf("License detection: %d known, %d unknown (%.0f%%).", insight.LicenseDetected, insight.LicenseUnknown, insight.LicensePct))
	return sec, true
}

func evidenceSection(insight ports.ReportInsight) (ports.ReportSection, bool) {
	if insight.EvidenceCount == 0 {
		return ports.ReportSection{}, false
	}
	sec := ports.ReportSection{Heading: "Evidence & Chain of Custody"}
	state := "INTACT"
	if !insight.EvidenceIntact {
		state = "BROKEN"
	}
	sec.Paragraphs = append(sec.Paragraphs, fmt.Sprintf("Evidence ledger: %d entries, hash chain %s.", insight.EvidenceCount, state))
	if insight.EvidenceHead != "" {
		sec.Paragraphs = append(sec.Paragraphs, "Ledger head (sha256): "+insight.EvidenceHead)
	}
	if insight.EvidenceAttested {
		sec.Paragraphs = append(sec.Paragraphs,
			"Origin: the chain head is signed (ed25519) by key "+insight.EvidenceKeyID+", proving this evidence originated from this instance – not only that it is internally consistent.")
	}
	return sec, true
}

// authorizationWindow renders the engagement's legal testing window (UTC dates).
func authorizationWindow(eng *engagement.Engagement) string {
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

// executivePosture is the one-line risk verdict, derived from the (filtered) findings
// and the scan confidence.
func executivePosture(findings []finding.Finding, insight ports.ReportInsight) string {
	counts := severityCounts(findings)
	crit, high := counts[shared.SeverityCritical], counts[shared.SeverityHigh]
	switch {
	case crit > 0:
		return fmt.Sprintf("Overall posture: HIGH RISK – %d critical and %d high-severity finding(s) require prompt remediation.", crit, high)
	case high > 0:
		return fmt.Sprintf("Overall posture: ELEVATED RISK – %d high-severity finding(s) should be remediated.", high)
	case len(findings) > 0:
		return "Overall posture: LOW RISK – findings were identified, none critical or high."
	case insight.HasScan && !insight.Confident:
		return "Overall posture: INCONCLUSIVE – no findings, but the scan was incomplete; treat as indicative."
	default:
		return "Overall posture: no findings at or above the reporting threshold were identified."
	}
}

// priorityDistribution renders the P1..P5 risk-priority tallies deterministically.
func priorityDistribution(findings []finding.Finding) string {
	counts := map[int]int{}
	for _, f := range findings {
		if f.Priority >= 1 && f.Priority <= 5 {
			counts[f.Priority]++
		}
	}
	parts := make([]string, 0, 5)
	for p := 1; p <= 5; p++ {
		if n := counts[p]; n > 0 {
			parts = append(parts, fmt.Sprintf("P%d: %d", p, n))
		}
	}
	return strings.Join(parts, "   ")
}

var severityOrder = []shared.Severity{
	shared.SeverityCritical, shared.SeverityHigh, shared.SeverityMedium,
	shared.SeverityLow, shared.SeverityInfo, shared.SeverityUnknown,
}

func severityCounts(findings []finding.Finding) map[shared.Severity]int {
	n := map[shared.Severity]int{}
	for _, f := range findings {
		switch f.Severity {
		case shared.SeverityCritical, shared.SeverityHigh, shared.SeverityMedium, shared.SeverityLow, shared.SeverityInfo:
			n[f.Severity]++
		default:
			n[shared.SeverityUnknown]++
		}
	}
	return n
}

func titleCase(s string) string {
	if s == "" {
		return ""
	}
	parts := strings.Fields(s)
	for i, p := range parts {
		r := []rune(p)
		r[0] = []rune(strings.ToUpper(string(r[0])))[0]
		parts[i] = string(r)
	}
	return strings.Join(parts, " ")
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
