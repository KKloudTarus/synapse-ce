package sbom

import (
	"sort"
	"strings"
)

// EcosystemCoverage is the per-ecosystem component tally for a generated SBOM: how many components
// of each ecosystem were emitted and how many carry a resolved (pinned) version. It makes per-ecosystem
// coverage VISIBLE so a partially-resolved ecosystem is not a silent gap hidden behind the single global
// completeness number – e.g. "npm 8/8 resolved, PyPI 2/5 resolved" tells an analyst exactly where the
// dependency picture is thin. Ecosystem is the PURL type ("pypi", "npm", "golang", "maven", …); components
// with no usable PURL are grouped under "(no purl)" so nothing is silently dropped from the tally.
type EcosystemCoverage struct {
	Ecosystem  string `json:"ecosystem"`
	Components int    `json:"components"`
	Resolved   int    `json:"resolved"` // components with a resolved version (sbom.IsResolvedVersion: not ""/unknown/latest/floating range)
}

// CoverageByEcosystem tallies an SBOM's components per ecosystem (by PURL type), counting how many carry a
// resolved version. Deterministic (sorted by ecosystem). Pure – no I/O. This is the per-ecosystem view that
// complements the scan's single global Completeness number.
func CoverageByEcosystem(s SBOM) []EcosystemCoverage {
	type tally struct{ components, resolved int }
	by := map[string]*tally{}
	for _, c := range s.Components {
		eco := ecosystemFromPURL(c.PURL)
		t := by[eco]
		if t == nil {
			t = &tally{}
			by[eco] = t
		}
		t.components++
		if IsResolvedVersion(c.Version) { // same "resolved" semantic as Completeness/FindingQuality (rejects ""/unknown/latest/floating ranges)
			t.resolved++
		}
	}
	out := make([]EcosystemCoverage, 0, len(by))
	for eco, t := range by {
		out = append(out, EcosystemCoverage{Ecosystem: eco, Components: t.components, Resolved: t.resolved})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ecosystem < out[j].Ecosystem })
	return out
}

// noPURL is the bucket for components without a usable PURL (local/first-party modules, or a malformed
// PURL) – kept visible rather than dropped, so the tally always sums to len(Components).
const noPURL = "(no purl)"

// ecosystemFromPURL extracts the ecosystem (the PURL type) from a package URL of the form
// "pkg:TYPE/namespace/name@version" – the type is the segment between "pkg:" and the first "/". A
// missing / non-"pkg:" / malformed PURL maps to noPURL so those components remain counted.
func ecosystemFromPURL(purl string) string {
	p := strings.TrimSpace(purl)
	const prefix = "pkg:"
	if !strings.HasPrefix(p, prefix) {
		return noPURL
	}
	rest := p[len(prefix):]
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return noPURL
	}
	return strings.ToLower(rest[:slash])
}
