package advisory

import (
	"sort"
	"strings"
)

// Range is one OSV `affected[].ranges[]` entry: a type + ordered boundary events. SEMVER ranges match by
// strict SemVer; ECOSYSTEM ranges match by the ecosystem's own ordering (SemVer for Go/npm/crates.io, PEP
// 440 for PyPI); GIT ranges (and ecosystems without an owned comparator) are skipped – see schemeFor.
type Range struct {
	Type   string  // "SEMVER" | "ECOSYSTEM" | "GIT"
	Events []Event // introduced / fixed / last_affected boundaries
}

// Event is one OSV range boundary – exactly one field is set. "introduced":"0" means "from the beginning".
type Event struct {
	Introduced   string
	Fixed        string
	LastAffected string
}

// Affected is the matcher entry point: a version is affected by an advisory if it is in the advisory's
// explicit affected-versions list OR falls in one of its version ranges (OSV treats these as alternatives).
// Ranges are matched with the ECOSYSTEM's ordering (SemVer for Go/npm/crates.io, PEP 440 for PyPI, …); a
// range type/ecosystem with no sound owned comparator – including every GIT range – is skipped, so the
// explicit versions list is the only signal there (a guessed order would risk a false match). This is what
// the owned DetectionSource calls; it queries the owned store, no third-party service.
func Affected(ecosystem, version string, ranges []Range, versions []string) bool {
	return AffectedVersionList(version, versions) || affectedRanges(ecosystem, version, ranges)
}

// AffectedVersionList reports whether version is in an OSV `affected[].versions` explicit enumeration. This
// is an EXACT, ecosystem-agnostic match (zero false positives/negatives) – the most authoritative signal
// an advisory carries, complementing the range match. A leading 'v' is normalized on both sides so a
// "1.2.3" component matches a "v1.2.3" listing and vice-versa; otherwise the published string must match.
func AffectedVersionList(version string, versions []string) bool {
	if version == "" {
		return false
	}
	v := normalizeVersionToken(version)
	for _, x := range versions {
		if normalizeVersionToken(x) == v {
			return true
		}
	}
	return false
}

func normalizeVersionToken(s string) string {
	return strings.TrimPrefix(strings.TrimSpace(s), "v")
}

// AffectedSemver reports whether version falls in any SEMVER-type range (ecosystem-agnostic strict SemVer):
// >= an "introduced" bound and strictly < the next "fixed" (or <= a "last_affected"), per the OSV schema. It
// is the ecosystem-less helper – ECOSYSTEM/GIT ranges need an ecosystem to choose an ordering and are skipped
// here. An empty/unparseable version is never affected (fail-closed).
func AffectedSemver(version string, ranges []Range) bool {
	return affectedRanges("", version, ranges)
}

// scheme is the version ordering for one (ecosystem, range-type): how to compare two version strings, and
// which strings it can soundly parse (the fail-closed gate). A range whose (ecosystem, type) has no scheme is
// skipped – the matcher never guesses an order it can't justify.
type scheme struct {
	compare func(a, b string) int
	valid   func(string) bool
}

var (
	semverScheme = scheme{compare: CompareSemver, valid: validCore}
	pep440Scheme = scheme{compare: comparePEP440, valid: validPEP440}
)

// schemeFor picks the ordering for a range. A SEMVER-type range is strict SemVer for ANY ecosystem (that is
// what the OSV type asserts). An ECOSYSTEM-type range uses the ecosystem's own ordering: SemVer for the
// SemVer-versioned ecosystems, PEP 440 for PyPI, and the owned Maven / RubyGems / NuGet comparators
// (versions_eco.go). GIT ranges, unknown types, and any ecosystem still without an owned comparator return
// ok=false → the range is skipped (the explicit versions list is then the only signal), so a version is
// never silently mis-ordered into a false match.
func schemeFor(ecosystem, rangeType string) (scheme, bool) {
	switch rangeType {
	case "SEMVER":
		return semverScheme, true
	case "ECOSYSTEM":
		switch ecosystem {
		case "Go", "npm", "crates.io":
			return semverScheme, true
		case "PyPI":
			return pep440Scheme, true
		case "Maven":
			return mavenScheme, true
		case "RubyGems":
			return rubygemsScheme, true
		case "NuGet":
			return nugetScheme, true
		}
		// OS-package families (Debian/Ubuntu/Alpine/RPM distros) use the distro's native ordering;
		// their OSV ecosystem names are release-versioned ("Debian:10", "Alpine:v3.18", …).
		if s, ok := osFamilyScheme(ecosystem); ok {
			return s, true
		}
	}
	return scheme{}, false
}

// affectedRanges reports whether version falls in any of the advisory's ranges, each matched with its
// (ecosystem, type) scheme. A range with no scheme (GIT, or an unsupported ecosystem ordering) is skipped; a
// version the scheme can't parse fails closed (skipped) rather than matching.
func affectedRanges(ecosystem, version string, ranges []Range) bool {
	for _, r := range ranges {
		sc, ok := schemeFor(ecosystem, r.Type)
		if !ok || !sc.valid(version) {
			continue
		}
		if affectedInRange(version, r.Events, sc) {
			return true
		}
	}
	return false
}

// affectedInRange walks one range's events in version order. OSV semantics: events partition the version
// line into alternating not-affected / affected intervals; "introduced" opens an affected interval, "fixed"
// closes it (exclusive), "last_affected" closes it (inclusive). A version is affected iff the most recent
// boundary at or before it is an "introduced".
func affectedInRange(version string, events []Event, sc scheme) bool {
	type bound struct {
		v    string
		kind int // 0 introduced, 1 fixed (exclusive), 2 last_affected (inclusive)
	}
	var bounds []bound
	for _, e := range events {
		switch {
		case e.Introduced != "":
			v := e.Introduced
			if v == "0" {
				v = "0.0.0" // OSV "from the beginning" (a valid zero in every scheme)
			}
			if sc.valid(v) { // skip a malformed advisory bound rather than corrupt the walk (#3/#4)
				bounds = append(bounds, bound{v: v, kind: 0})
			}
		case e.Fixed != "":
			if sc.valid(e.Fixed) {
				bounds = append(bounds, bound{v: e.Fixed, kind: 1})
			}
		case e.LastAffected != "":
			if sc.valid(e.LastAffected) {
				bounds = append(bounds, bound{v: e.LastAffected, kind: 2})
			}
		}
	}
	if len(bounds) == 0 {
		return false
	}
	// Sort by VERSION only, STABLY – so events sharing a version keep their input (timeline) order. This
	// replays the OSV event timeline faithfully (#1): a `fixed` then a re-`introduced` at the same version
	// re-opens the interval; an `introduced` then a `fixed` at the same version is a zero-width exclusion.
	// (A kind-based tie-break would conflate those two and silently mark a re-opened range clean.)
	sort.SliceStable(bounds, func(i, j int) bool {
		return sc.compare(bounds[i].v, bounds[j].v) < 0
	})
	affected := false
	for _, b := range bounds {
		cmp := sc.compare(version, b.v)
		if cmp < 0 {
			break // all remaining boundaries are above the version
		}
		switch b.kind {
		case 0: // introduced: affected from here on (until a close)
			affected = true
		case 1: // fixed (exclusive): version >= fixed is NOT affected by this interval
			affected = false
		case 2: // last_affected (inclusive): affected up to and INCLUDING this version
			affected = cmp <= 0
		}
	}
	return affected
}
