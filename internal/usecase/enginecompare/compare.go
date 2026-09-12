// Package enginecompare produces an honest differential between two vulnerability detection engines run over
// the SAME SBOM: which (component, CVE) pairs each engine found, and specifically what the candidate (the
// owned Synapse engine) found that a baseline competitor (e.g. Grype) missed, and vice versa. It computes no
// pass/fail verdict and invents no ground truth — it reports the set difference of two real runs, so a
// "Synapse matched or beat Grype here" claim is always backed by an actual comparison, never asserted.
package enginecompare

import (
	"context"
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
	base, cand := pairSet(baseline), pairSet(candidate)
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
