// Package enginecompare produces an honest differential between two vulnerability detection engines run over
// the SAME SBOM: which (component, CVE) pairs each engine found, and specifically what the candidate (the
// owned Synapse engine) found that a baseline competitor (e.g. Grype) missed, and vice versa. It computes no
// pass/fail verdict and invents no ground truth — it reports the set difference of two real runs, so a
// "Synapse matched or beat Grype here" claim is always backed by an actual comparison, never asserted.
package enginecompare

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Divergence is one (component, CVE) pair found by one engine and not the other.
type Divergence struct {
	Component string `json:"component"`
	CVE       string `json:"cve"`
}

// Report is the differential of two engines over one SBOM. CandidateOnly is what the owned engine found that
// the baseline missed (extra coverage); BaselineOnly is what the baseline found that the owned engine missed
// (a recall gap to investigate). Both counts are of DISTINCT (component, CVE) pairs, so multiple advisories
// for the same pair collapse to one.
type Report struct {
	BaselineName   string `json:"baseline_name"`
	CandidateName  string `json:"candidate_name"`
	ComponentCount int    `json:"component_count"`

	BaselinePairs  int `json:"baseline_pairs"`
	CandidatePairs int `json:"candidate_pairs"`
	Both           int `json:"both"`

	CandidateOnly []Divergence `json:"candidate_only"`
	BaselineOnly  []Divergence `json:"baseline_only"`

	// CandidateMatchesBaselineRecall is true when the candidate found EVERY (component, CVE) the baseline did
	// (BaselineOnly is empty) FOR THIS run and input. It is a statement about this comparison, not a universal
	// claim, and it is false the moment the baseline surfaces one pair the candidate missed.
	CandidateMatchesBaselineRecall bool `json:"candidate_matches_baseline_recall"`
}

// InputIdentity binds a comparison to one immutable catalog target and SBOM input.
type InputIdentity struct {
	CatalogRevision string `json:"catalog_revision"`
	CatalogDigest   string `json:"catalog_digest"`
	TargetDigest    string `json:"target_digest"`
	SBOMDigest      string `json:"sbom_digest"`
}

// EngineFindingSet is one precomputed engine's findings for a shared immutable input. It carries no oracle truth.
type EngineFindingSet struct {
	Name          string
	InputIdentity InputIdentity
	Findings      []vulnerability.RawFinding
}

// MultiReport independently compares a candidate with every supplied baseline. It is diagnostic only and
// deliberately contains no oracle or gate verdict.
type MultiReport struct {
	DiagnosticOnly bool          `json:"diagnostic_only"`
	CandidateName  string        `json:"candidate_name"`
	InputIdentity  InputIdentity `json:"input_identity"`
	Comparisons    []Report      `json:"comparisons"`
}

const maxCompareManyBaselines = 3

// canonicalCVE upper-cases a CVE-shaped id ("cve-2024-1" -> "CVE-2024-1") so two engines that spell the same
// CVE differently compare equal; it returns "" for a non-CVE id.
func canonicalCVE(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(strings.ToUpper(s), "CVE-") {
		return strings.ToUpper(s)
	}
	return ""
}

// canonicalID normalizes a fallback (non-CVE) advisory id for keying. It case-folds only the id schemes that
// are DEFINED to be case-insensitive (CVE, GHSA); any other id (a vendor id, a URL-shaped advisory ref, which
// can be case-sensitive) is preserved exactly, so two genuinely different advisories are never collapsed into
// one key (which would hide a recall gap and overstate the candidate).
func canonicalID(s string) string {
	s = strings.TrimSpace(s)
	if cve := canonicalCVE(s); cve != "" {
		return cve
	}
	if strings.HasPrefix(strings.ToUpper(s), "GHSA-") {
		return strings.ToUpper(s)
	}
	return s
}

// keysFor expands a raw finding to the set of (component, id) pairs it asserts: ONE per DISTINCT CVE id it
// carries (its primary id and every alias, canonicalized), so a finding that aliases several CVEs is compared
// per CVE and a real recall gap on one of them is never hidden by agreement on another. A finding that
// carries no CVE id falls back to its primary advisory id (upper-cased for case-insensitive matching) so it
// still contributes one pair rather than being dropped. A finding with no component, or no id at all,
// contributes nothing (it cannot be soundly compared).
func keysFor(r vulnerability.RawFinding) []Divergence {
	comp := strings.TrimSpace(r.Component)
	if comp == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []Divergence
	for _, cand := range append([]string{r.AdvisoryID}, r.Aliases...) {
		if cve := canonicalCVE(cand); cve != "" && !seen[cve] {
			seen[cve] = true
			out = append(out, Divergence{Component: comp, CVE: cve})
		}
	}
	if len(out) == 0 { // no CVE id anywhere: fall back to the primary advisory id so the finding still counts
		if id := canonicalID(r.AdvisoryID); id != "" {
			out = append(out, Divergence{Component: comp, CVE: id})
		}
	}
	return out
}

func pairSet(findings []vulnerability.RawFinding) map[Divergence]bool {
	out := make(map[Divergence]bool, len(findings))
	for _, f := range findings {
		for _, d := range keysFor(f) {
			out[d] = true
		}
	}
	return out
}

// Compare computes the differential of two already-produced finding sets. It is pure (no I/O), so a CI job
// that has both engines' outputs can reduce them deterministically.
func Compare(baselineName, candidateName string, baseline, candidate []vulnerability.RawFinding) Report {
	return comparePairSets(baselineName, candidateName, pairSet(baseline), pairSet(candidate))
}

func comparePairSets(baselineName, candidateName string, base, cand map[Divergence]bool) Report {
	rep := Report{
		BaselineName:   baselineName,
		CandidateName:  candidateName,
		BaselinePairs:  len(base),
		CandidatePairs: len(cand),
		// Non-nil so an empty differential serializes as [] (a clean "no divergence"), not null.
		CandidateOnly: []Divergence{},
		BaselineOnly:  []Divergence{},
	}
	for d := range cand {
		if base[d] {
			rep.Both++
		} else {
			rep.CandidateOnly = append(rep.CandidateOnly, d)
		}
	}
	for d := range base {
		if !cand[d] {
			rep.BaselineOnly = append(rep.BaselineOnly, d)
		}
	}
	sortDivergences(rep.CandidateOnly)
	sortDivergences(rep.BaselineOnly)
	rep.CandidateMatchesBaselineRecall = len(rep.BaselineOnly) == 0
	return rep
}

// Validate verifies that a comparison input is fully content-addressed.
func (identity InputIdentity) Validate() error {
	if strings.TrimSpace(identity.CatalogRevision) == "" {
		return fmt.Errorf("catalog revision is required")
	}
	for _, digest := range []struct {
		name  string
		value string
	}{
		{name: "catalog", value: identity.CatalogDigest},
		{name: "target", value: identity.TargetDigest},
		{name: "SBOM", value: identity.SBOMDigest},
	} {
		if !validSHA256Digest(digest.value) {
			return fmt.Errorf("%s digest must be an immutable sha256 digest", digest.name)
		}
	}
	return nil
}

func validSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

// CompareMany compares the candidate independently with every named baseline using the same canonical-ID
// semantics as Compare. Names are required and unique, and every finding set must bind the same immutable input.
func CompareMany(candidate EngineFindingSet, baselines []EngineFindingSet) (MultiReport, error) {
	if err := candidate.InputIdentity.Validate(); err != nil {
		return MultiReport{}, fmt.Errorf("candidate input identity: %w", err)
	}
	candidateName := strings.TrimSpace(candidate.Name)
	if candidateName == "" {
		return MultiReport{}, fmt.Errorf("candidate name is required")
	}
	if len(baselines) == 0 {
		return MultiReport{}, fmt.Errorf("at least one baseline is required")
	}
	if len(baselines) > maxCompareManyBaselines {
		return MultiReport{}, fmt.Errorf("at most %d baselines are supported", maxCompareManyBaselines)
	}
	candidatePairs := pairSet(candidate.Findings)
	seen := map[string]struct{}{candidateName: {}}
	report := MultiReport{
		DiagnosticOnly: true,
		CandidateName:  candidateName,
		InputIdentity:  candidate.InputIdentity,
		Comparisons:    make([]Report, 0, len(baselines)),
	}
	for i, baseline := range baselines {
		if err := baseline.InputIdentity.Validate(); err != nil {
			return MultiReport{}, fmt.Errorf("baseline %d input identity: %w", i, err)
		}
		if baseline.InputIdentity != candidate.InputIdentity {
			return MultiReport{}, fmt.Errorf("baseline %d input identity does not match candidate", i)
		}
		baselineName := strings.TrimSpace(baseline.Name)
		if baselineName == "" {
			return MultiReport{}, fmt.Errorf("baseline %d name is required", i)
		}
		if _, exists := seen[baselineName]; exists {
			return MultiReport{}, fmt.Errorf("engine name %q is duplicated or collides with candidate", baselineName)
		}
		seen[baselineName] = struct{}{}
		report.Comparisons = append(report.Comparisons, comparePairSets(baselineName, candidateName, pairSet(baseline.Findings), candidatePairs))
	}
	sort.Slice(report.Comparisons, func(i, j int) bool { return report.Comparisons[i].BaselineName < report.Comparisons[j].BaselineName })
	return report, nil
}

// Run scans doc with both engines and compares them. Errors from either engine abort (a partial scan would
// produce a misleading differential). Both engines must implement the shared DetectionSource port, so the
// owned engine and any competitor adapter (e.g. Grype) can be compared without special-casing either.
func Run(ctx context.Context, baseline, candidate ports.DetectionSource, doc *sbom.SBOM) (Report, error) {
	baseFindings, err := baseline.Scan(ctx, doc)
	if err != nil {
		return Report{}, err
	}
	candFindings, err := candidate.Scan(ctx, doc)
	if err != nil {
		return Report{}, err
	}
	rep := Compare(baseline.Name(), candidate.Name(), baseFindings, candFindings)
	if doc != nil {
		rep.ComponentCount = len(doc.Components)
	}
	return rep, nil
}

func sortDivergences(ds []Divergence) {
	sort.Slice(ds, func(i, j int) bool {
		if ds[i].Component != ds[j].Component {
			return ds[i].Component < ds[j].Component
		}
		return ds[i].CVE < ds[j].CVE
	})
}
