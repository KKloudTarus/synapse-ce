package advisory

import (
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// CPEMatches reports whether a component's CPE falls within one advisory CPE applicability statement.
//   - matched:   the component is within the statement's version constraint (a hit, when the statement is Vulnerable).
//   - ranged:    the statement constrained by a version RANGE (versionStart/End*) rather than an exact version.
//   - evaluable: the version constraint could be compared at all; false means the caller must treat the
//     pairing as unmatchable (surface the coverage gap) rather than silently drop it.
//
// It shares the fuzzy comparator (OrderableFuzzy/CompareFuzzy) with the package-range matcher so the
// primary scan (ownadvisory.Source) and the reconciliation path order NVD versions identically. It does
// not itself check current.Vulnerable; the caller decides whether a non-vulnerable statement matters.
func CPEMatches(criteria, component sbom.CPE23, current CPEMatch) (matched, ranged, evaluable bool) {
	if !criteria.MatchAttributes(component) {
		return false, false, true
	}
	version := component.Version
	if version == "" || version == "*" || version == "-" {
		return false, false, false
	}
	if criteria.Version != "*" {
		if criteria.Version == "-" {
			return false, false, true
		}
		return strings.EqualFold(criteria.Version, version), false, true
	}
	bounds := []string{current.VersionStartIncluding, current.VersionStartExcluding, current.VersionEndIncluding, current.VersionEndExcluding}
	hasBounds := false
	for _, bound := range bounds {
		if bound == "" {
			continue
		}
		hasBounds = true
		if !OrderableFuzzy(bound) || !OrderableFuzzy(version) {
			return false, true, false
		}
	}
	if !hasBounds {
		return true, false, true
	}
	if current.VersionStartIncluding != "" && CompareFuzzy(version, current.VersionStartIncluding) < 0 {
		return false, true, true
	}
	if current.VersionStartExcluding != "" && CompareFuzzy(version, current.VersionStartExcluding) <= 0 {
		return false, true, true
	}
	if current.VersionEndIncluding != "" && CompareFuzzy(version, current.VersionEndIncluding) > 0 {
		return false, true, true
	}
	if current.VersionEndExcluding != "" && CompareFuzzy(version, current.VersionEndExcluding) >= 0 {
		return false, true, true
	}
	return true, true, true
}
