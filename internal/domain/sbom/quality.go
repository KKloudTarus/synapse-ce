package sbom

import (
	"fmt"
	"sort"
	"strings"
)

// SBOM QUALITY scoring — a first-class, surfaced measure of how well a PRODUCED SBOM describes its
// components, scored against the NTIA "minimum elements" (NTIA 2021, the baseline EO 14028 / EU CRA
// consumers increasingly require) plus a few CycloneDX/SPDX semantic-quality checks. It is deliberately
// DISTINCT from Completeness: Completeness judges scan COVERAGE ("did we capture the dependencies");
// QualityReport judges the DOCUMENT ("are the captured components described well enough to act on, share,
// or satisfy a regulatory minimum"). A thin SBOM that omits suppliers or checksums is a supply-chain risk
// even when coverage is perfect, so — per Synapse's "no silent gap" posture — that shortfall is measured
// and reported rather than assumed away. The scorer is pure + deterministic (no I/O, sorted output):
// same SBOM ⇒ same report.
//
// This is Synapse's own take on what interlynk's `sbomqs` does; the checks are reimplemented over the
// native domain model, not delegated to any external tool.

// QualityCategory groups the scored elements.
const (
	QualityCategoryNTIA     = "ntia"     // an NTIA-2021 minimum element
	QualityCategorySemantic = "semantic" // a CycloneDX/SPDX describe-quality check beyond the NTIA floor
)

// NTIAThreshold is the per-element score (0..100) at or above which an NTIA minimum element is treated as
// satisfied for the SBOM as a whole. It is intentionally strict-but-not-perfect: a handful of components
// missing a field should visibly lower the element, but one un-decodable PURL should not fail an otherwise
// complete SBOM. Callers wanting a hard gate compare QualityReport.NTIAScore against their own bar.
const NTIAThreshold = 90

// QualityElement is one scored quality dimension. For component-level checks, Present/Total are component
// counts; for document-level checks (author, timestamp, dependency relationships) Total is 1 and Present is
// 0 or 1. Score is round(100*Present/Total), or 0 when Total is 0 (an empty SBOM describes nothing).
type QualityElement struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Category string `json:"category"`
	Present  int    `json:"present"`
	Total    int    `json:"total"`
	Score    int    `json:"score"`            // 0..100 for this element
	Detail   string `json:"detail,omitempty"` // short, human explanation when Score < 100
}

// QualityReport is the overall SBOM-quality verdict: a blended 0..100 Score (NTIA weighted over semantic),
// an NTIA-only sub-score, whether every NTIA element clears NTIAThreshold, and the per-element breakdown so
// exactly which dimension is thin stays visible. A caller reads QualityReport from ScanResult.SBOMQuality;
// gate on len(Elements) > 0 to tell "not computed" (a recon-only / nil-SBOM run) from a real 0 score.
type QualityReport struct {
	// Score is a HUMAN HEADLINE only. A hard gate MUST key off NTIAMet / NTIAScore, never Score: Score blends
	// in semantic quality, so on its own it must never read "passing" while a mandatory NTIA element is
	// absent. It is therefore clamped below NTIAThreshold whenever NTIAMet is false.
	Score     int              `json:"score"`      // blended 0..100 (NTIA 70% + semantic 30%), clamped < NTIAThreshold when !NTIAMet
	NTIAScore int              `json:"ntia_score"` // mean of the NTIA element scores, 0..100
	NTIAMet   bool             `json:"ntia_met"`   // every NTIA element Score >= NTIAThreshold
	Elements  []QualityElement `json:"elements"`
	// Profiles projects the scored elements onto named compliance profiles (NTIA 2021, vulnerability-lookup
	// readiness, ...) as explicit PASS/FAIL with the failing requirements named — the citable governance
	// artifact a regulated buyer asks for, distinct from the raw score.
	Profiles []ProfileResult `json:"profiles"`
	Summary  string          `json:"summary"`
}

// ProfileResult is a QualityReport projected onto one named compliance profile: whether every required
// element clears the bar, and the labels of those that did not.
type ProfileResult struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Met     bool     `json:"met"`
	Missing []string `json:"missing,omitempty"` // labels of required elements below the profile threshold
	Summary string   `json:"summary"`
}

// complianceProfile is a named set of required QualityElement IDs — a regulation or standard's expected
// subset. Each required element must score >= NTIAThreshold for the profile to be met.
type complianceProfile struct {
	id, name string
	required []string
}

// complianceProfiles are the built-in, curated profiles. NTIA-2021 is the authoritative minimum-elements
// baseline (EO 14028); vuln-lookup is the narrower "can every component be matched against an advisory DB"
// readiness check (name + version + a unique identifier). Both are LLM-free, deterministic tables. More
// profiles (NTIA-2025, BSI TR-03183-2, OWASP SCVS levels) slot in here as their mappings are curated.
var complianceProfiles = []complianceProfile{
	{id: "ntia-2021", name: "NTIA 2021 minimum elements", required: []string{
		"ntia-supplier", "ntia-name", "ntia-version", "ntia-uniqid", "ntia-dependencies", "ntia-author", "ntia-timestamp",
	}},
	{id: "vuln-lookup", name: "Vulnerability lookup readiness", required: []string{
		"ntia-name", "ntia-version", "ntia-uniqid",
	}},
}

// evaluateProfiles projects the scored elements onto the built-in compliance profiles. Deterministic: the
// profile order and the missing-labels order follow the fixed tables above.
func evaluateProfiles(elements []QualityElement) []ProfileResult {
	byID := make(map[string]QualityElement, len(elements))
	for _, e := range elements {
		byID[e.ID] = e
	}
	out := make([]ProfileResult, 0, len(complianceProfiles))
	for _, p := range complianceProfiles {
		pr := ProfileResult{ID: p.id, Name: p.name, Met: true}
		for _, id := range p.required {
			e, ok := byID[id]
			if !ok || e.Score < NTIAThreshold {
				pr.Met = false
				if ok {
					pr.Missing = append(pr.Missing, e.Label)
				} else {
					pr.Missing = append(pr.Missing, id)
				}
			}
		}
		if pr.Met {
			pr.Summary = fmt.Sprintf("%s: PASS", p.name)
		} else {
			pr.Summary = fmt.Sprintf("%s: FAIL (missing: %s)", p.name, strings.Join(pr.Missing, ", "))
		}
		out = append(out, pr)
	}
	return out
}

// Quality scores an SBOM against the NTIA minimum elements and semantic-quality checks. Pure + deterministic.
func Quality(s SBOM) QualityReport {
	n := len(s.Components)
	// Component-level tallies (single pass).
	var withSupplier, withName, withVersionField, withPURL, withLicense, withSPDXLicense, withChecksum int
	for _, c := range s.Components {
		if supplierOf(c) != "" {
			withSupplier++
		}
		if strings.TrimSpace(c.Name) != "" {
			withName++
		}
		if strings.TrimSpace(c.Version) != "" { // NTIA "version" = the field is populated; pinned-ness is Completeness's job
			withVersionField++
		}
		if strings.TrimSpace(c.PURL) != "" {
			withPURL++
		}
		if len(c.Licenses) > 0 {
			withLicense++
			for _, l := range c.Licenses {
				if strings.TrimSpace(l.SPDXID) != "" {
					withSPDXLicense++
					break
				}
			}
		}
		if HasChecksum(c) {
			withChecksum++
		}
	}

	comp := func(id, label, category string, present int, missingHint string) QualityElement {
		e := QualityElement{ID: id, Label: label, Category: category, Present: present, Total: n, Score: ratioScore(present, n)}
		if e.Score < 100 {
			if n == 0 {
				e.Detail = "SBOM has no components to describe"
			} else {
				e.Detail = fmt.Sprintf("%d of %d components %s", n-present, n, missingHint)
			}
		}
		return e
	}
	doc := func(id, label string, ok bool, missing string) QualityElement {
		e := QualityElement{ID: id, Label: label, Category: QualityCategoryNTIA, Present: b2i(ok), Total: 1, Score: b2i(ok) * 100}
		if !ok {
			e.Detail = missing
		}
		return e
	}

	elements := []QualityElement{
		// NTIA minimum elements (NTIA 2021).
		comp("ntia-supplier", "Supplier name", QualityCategoryNTIA, withSupplier, "have no declared or derivable supplier (no supplier field and no PURL namespace)"),
		comp("ntia-name", "Component name", QualityCategoryNTIA, withName, "have no name"),
		comp("ntia-version", "Version", QualityCategoryNTIA, withVersionField, "have no version"),
		comp("ntia-uniqid", "Unique identifier (PURL)", QualityCategoryNTIA, withPURL, "have no PURL"),
		doc("ntia-dependencies", "Dependency relationships", len(s.Dependencies) > 0,
			"the SBOM expresses no dependency-graph relationships (a flat component list)"),
		doc("ntia-author", "Author of SBOM data", strings.TrimSpace(s.Source) != "", "the SBOM records no author/generator"),
		doc("ntia-timestamp", "Timestamp", !s.Audit.CreatedAt.IsZero(), "the SBOM records no creation timestamp"),
		// Semantic quality beyond the NTIA floor.
		comp("sem-license", "License present", QualityCategorySemantic, withLicense, "have no license"),
		comp("sem-license-spdx", "License is an SPDX id", QualityCategorySemantic, withSPDXLicense, "have no SPDX-valid license id"),
		comp("sem-checksum", "Checksum", QualityCategorySemantic, withChecksum, "have no integrity checksum"),
	}
	sort.SliceStable(elements, func(i, j int) bool {
		if elements[i].Category != elements[j].Category {
			return elements[i].Category < elements[j].Category // "ntia" before "semantic"
		}
		return elements[i].ID < elements[j].ID
	})

	r := QualityReport{Elements: elements}
	r.NTIAScore, r.NTIAMet = ntiaScore(elements)
	// semantic checks are always present in the fixed element list above; the hasSem guard is kept so a
	// future rubric change that drops them can't divide by zero.
	if semScore, hasSem := categoryMean(elements, QualityCategorySemantic); hasSem {
		r.Score = roundDiv(r.NTIAScore*70+semScore*30, 100)
	} else {
		r.Score = r.NTIAScore
	}
	// The blended headline must never read "passing" while a mandatory NTIA element is absent: clamp it below
	// the threshold whenever NTIAMet is false, so a gate that (wrongly) keys off Score still can't be fooled
	// by strong semantic quality masking a missing minimum element. NTIAScore/NTIAMet carry the full truth.
	if !r.NTIAMet && r.Score >= NTIAThreshold {
		r.Score = NTIAThreshold - 1
	}
	r.Profiles = evaluateProfiles(elements)
	r.Summary = qualitySummary(r)
	return r
}

// ntiaScore returns the mean of the NTIA element scores and whether every one clears NTIAThreshold.
func ntiaScore(elements []QualityElement) (score int, met bool) {
	mean, has := categoryMean(elements, QualityCategoryNTIA)
	met = has
	for _, e := range elements {
		if e.Category == QualityCategoryNTIA && e.Score < NTIAThreshold {
			met = false
		}
	}
	return mean, met
}

// categoryMean averages the element scores in a category; has is false when the category has no elements.
func categoryMean(elements []QualityElement, category string) (mean int, has bool) {
	sum, count := 0, 0
	for _, e := range elements {
		if e.Category == category {
			sum += e.Score
			count++
		}
	}
	if count == 0 {
		return 0, false
	}
	return roundDiv(sum, count), true
}

func qualitySummary(r QualityReport) string {
	if r.NTIAMet {
		return fmt.Sprintf("SBOM quality %d/100 (NTIA %d/100 — all minimum elements present).", r.Score, r.NTIAScore)
	}
	// Name the weakest NTIA elements so the shortfall is actionable, not just a number.
	var weak []string
	for _, e := range r.Elements {
		if e.Category == QualityCategoryNTIA && e.Score < NTIAThreshold {
			weak = append(weak, e.Label)
		}
	}
	return fmt.Sprintf("SBOM quality %d/100 (NTIA %d/100 — below the %d threshold on: %s).",
		r.Score, r.NTIAScore, NTIAThreshold, strings.Join(weak, ", "))
}

// SupplierSource values record how a component's Supplier was obtained (see Component.SupplierSource).
const (
	SupplierDeclared = "declared" // asserted by the producer or an imported/untrusted client SBOM
	SupplierDerived  = "derived"  // deterministically inferred by Synapse from the PURL namespace
)

// HasChecksum reports whether a component carries any integrity digest — the legacy SHA1 field or a
// Checksums entry — which is the semantic-quality "checksum present" signal (tamper evidence per component).
func HasChecksum(c Component) bool {
	return strings.TrimSpace(c.SHA1) != "" || len(c.Checksums) > 0
}

// supplierOf returns a component's supplier: the explicitly-captured Supplier when the producer/imported SBOM
// carried one, else one derived from the PURL namespace. Empty when neither yields one.
func supplierOf(c Component) string { return SupplierOr(c.Supplier, c.PURL) }

// SupplierOr prefers a producer-declared supplier name, falling back to the PURL-namespace derivation. It is
// the single home for the "captured, else derived" rule so every producer (Syft, owned parsers, importer),
// both SPDX exporters, and the scorer agree on how a component's supplier is resolved.
func SupplierOr(declared, purl string) string {
	s, _ := SupplierWithSource(declared, purl)
	return s
}

// SupplierWithSource resolves a component's supplier AND reports its provenance: a non-blank declared value
// wins as SupplierDeclared; else the PURL namespace is inferred as SupplierDerived; else ("", "").
func SupplierWithSource(declared, purl string) (supplier, source string) {
	if s := strings.TrimSpace(declared); s != "" {
		return s, SupplierDeclared
	}
	if s := SupplierFromPURL(purl); s != "" {
		return s, SupplierDerived
	}
	return "", ""
}

// SupplierFromPURL derives a component's supplier from its PURL namespace — the segment(s) between the PURL
// type and the package name (a Maven groupId, an npm scope, a GitHub org, a Docker image owner, ...), which
// the PURL spec defines as "a name prefix such as a Maven groupId, a Docker image owner, a GitHub user or
// organization". It is a conservative, deterministic attribution: a PURL with no namespace (e.g. a bare npm
// package like "pkg:npm/leftpad@1.0.0") yields "" rather than a guess. Used to score the NTIA supplier
// element without inventing data.
func SupplierFromPURL(purl string) string {
	p := strings.TrimSpace(purl)
	const prefix = "pkg:"
	if !strings.HasPrefix(p, prefix) {
		return ""
	}
	rest := p[len(prefix):]
	// Drop the type: "type/namespace.../name@version" -> "namespace.../name@version".
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return "" // no "/" after type => no namespace, just a bare name
	}
	rest = rest[slash+1:]
	// Strip qualifiers / version / subpath so they can't leak into the namespace.
	for _, sep := range []byte{'@', '?', '#'} {
		if i := strings.IndexByte(rest, sep); i >= 0 {
			rest = rest[:i]
		}
	}
	last := strings.LastIndexByte(rest, '/')
	if last <= 0 {
		return "" // only a name, no namespace
	}
	return purlDecode(rest[:last])
}

// purlDecode percent-decodes the small set of escapes a PURL namespace realistically carries (notably
// "%40" for the "@" in an npm scope), without pulling in net/url for a hot, pure path.
func purlDecode(s string) string {
	if !strings.ContainsRune(s, '%') {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if h, ok := hexByte(s[i+1], s[i+2]); ok {
				b.WriteByte(h)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hexByte(a, b byte) (byte, bool) {
	hi, ok1 := hexNibble(a)
	lo, ok2 := hexNibble(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	return hi<<4 | lo, true
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// ratioScore is floor(100*present/total), or 0 when total is 0. Floor (not round) so an element can never
// round UP across NTIAThreshold: 89.9% coverage scores 89, staying honestly below a 90 bar rather than
// clearing it, which keeps the NTIAMet gate exact (no ~0.5% of slack).
func ratioScore(present, total int) int {
	if total <= 0 {
		return 0
	}
	return present * 100 / total // integer division truncates toward zero == floor for non-negative inputs
}

// roundDiv divides with round-half-up (non-negative inputs).
func roundDiv(a, b int) int {
	if b == 0 {
		return 0
	}
	return (a + b/2) / b
}

func b2i(ok bool) int {
	if ok {
		return 1
	}
	return 0
}
