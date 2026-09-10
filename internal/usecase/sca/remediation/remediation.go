// Package remediation computes the smallest set of direct-dependency upgrades that removes a transitive
// vulnerability from a resolved dependency graph (EPIC #860 D3.8). It is pure and offline: it names WHICH
// direct dependencies must be upgraded, not the exact target versions (choosing a version that first pulls the
// fixed transitive needs registry metadata this graph does not carry).
package remediation

import "github.com/KKloudTarus/synapse-ce/internal/domain/sbom"

// Plan is the minimal-upgrade remediation for one vulnerable component.
type Plan struct {
	// Vulnerable is the vulnerable component's ref (PURL) as it appears in the graph.
	Vulnerable string
	// FixedVersion is the version that fixes the vulnerability (from the advisory), carried through for
	// remediation context; empty when the advisory declares no fix.
	FixedVersion string
	// DirectBumps is the minimal set of DIRECT (top-level) dependencies whose upgrade removes every path from a
	// root to the vulnerable component. It is sorted and deduplicated. When the vulnerable component is itself a
	// direct dependency, it is the single bump.
	DirectBumps []string
}

// Solve returns the minimal-upgrade plan for a vulnerable component, or ok=false when the component is not in
// the graph (nothing to remediate) or is reachable only through a dependency cycle (no clean set of direct
// introducers to bump).
//
// Minimality: every path from a root to the vulnerable component passes through exactly one DIRECT dependency
// (a top-level node), so the set of direct introducers is precisely the set that must change. Dropping any one
// of them leaves the paths that run through it, so no smaller set removes the vulnerability; upgrading all of
// them removes every path. sbom.IntroducedBy computes exactly that set (deduped, sorted, cycle-only -> empty).
func Solve(deps []sbom.Dependency, vulnerable, fixedVersion string) (Plan, bool) {
	introducers := sbom.IntroducedBy(deps, vulnerable)
	if len(introducers) == 0 {
		return Plan{}, false
	}
	return Plan{Vulnerable: vulnerable, FixedVersion: fixedVersion, DirectBumps: introducers}, true
}
