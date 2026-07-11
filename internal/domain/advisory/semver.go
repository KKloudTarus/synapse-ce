// Package advisory is the OWNED vulnerability-advisory matching brain: it decides
// whether a component version is affected by an advisory's version ranges WITHOUT querying a third-party
// service (OSV.dev / Grype), so detection does not depend on any one external matcher. This file is the
// SemVer 2.0 comparator + the OSV SEMVER range-membership query; it is pure + table-tested against
// the spec, so a match verdict is deterministic and reproducible.
package advisory

import "strings"

// CompareSemver orders two SemVer-2.0 versions: -1 if a < b, 0 if equal, +1 if a > b. Build metadata
// (everything after '+') is ignored for precedence (per spec §10); a leading 'v' is tolerated. Missing
// minor/patch are treated as 0 (so "1" == "1.0.0"), which matches how OSV bounds like "1" are read.
func CompareSemver(a, b string) int {
	ac, ap := splitSemver(a)
	bc, bp := splitSemver(b)
	// Core: numeric major.minor.patch.
	for i := 0; i < 3; i++ {
		if d := compareNum(ac[i], bc[i]); d != 0 {
			return d
		}
	}
	// Pre-release precedence (spec §11): a version WITH a pre-release is lower than one without.
	switch {
	case ap == "" && bp == "":
		return 0
	case ap == "": // a is the release, b is a pre-release of it → a > b
		return 1
	case bp == "":
		return -1
	}
	return comparePrerelease(ap, bp)
}

// splitSemver returns the [major, minor, patch] core (missing parts = "0") and the pre-release string
// (after '-', before any '+'). Build metadata is dropped.
func splitSemver(v string) ([3]string, string) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 { // drop build metadata
		v = v[:i]
	}
	pre := ""
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre = v[i+1:]
		v = v[:i]
	}
	parts := strings.SplitN(v, ".", 3)
	core := [3]string{"0", "0", "0"}
	for i := 0; i < len(parts) && i < 3; i++ {
		if parts[i] != "" {
			core[i] = parts[i]
		}
	}
	return core, pre
}

// compareNum compares two version core segments. All-digit segments compare as ARBITRARY-PRECISION
// non-negative integers (so a >19-digit id – a real OSV/date-stamped identifier – never falls back to a
// wrong lexical order, #2); a non-numeric segment is the matcher's fail-closed responsibility (validCore),
// so the lexical fallback here is only a defensive last resort.
func compareNum(a, b string) int {
	if isNumericStr(a) && isNumericStr(b) {
		return compareNumeric(a, b)
	}
	return strings.Compare(a, b)
}

// isNumericStr reports whether s is a non-empty run of ASCII digits.
func isNumericStr(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// compareNumeric orders two all-digit strings as non-negative integers of unbounded size: strip leading
// zeros, then the longer (more significant digits) wins, then byte-wise on equal length.
func compareNumeric(a, b string) int {
	a, b = trimLeadingZeros(a), trimLeadingZeros(b)
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

func trimLeadingZeros(s string) string {
	i := 0
	for i < len(s)-1 && s[i] == '0' {
		i++
	}
	return s[i:]
}

// validCore reports whether v's major.minor.patch are all numeric – the well-formedness the matcher
// fail-closes on (a garbage or over-long version like "abc" or "1.2.3.4" must never match an advisory).
func validCore(v string) bool {
	if strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "v")) == "" {
		return false
	}
	core, _ := splitSemver(v)
	for _, p := range core {
		if !isNumericStr(p) {
			return false
		}
	}
	return true
}

// comparePrerelease compares two non-empty pre-release strings per SemVer §11: dot-separated identifiers,
// numeric identifiers compared numerically, alphanumeric lexically in ASCII order, numeric < alphanumeric,
// and a larger set of identifiers outranks a smaller when all preceding are equal.
func comparePrerelease(a, b string) int {
	ai := strings.Split(a, ".")
	bi := strings.Split(b, ".")
	for i := 0; i < len(ai) && i < len(bi); i++ {
		x, y := ai[i], bi[i]
		xNum, yNum := isNumericStr(x), isNumericStr(y)
		switch {
		case xNum && yNum: // both numeric – arbitrary precision (no int overflow, #2)
			if d := compareNumeric(x, y); d != 0 {
				return d
			}
		case xNum: // numeric identifiers always have LOWER precedence than alphanumeric (§11)
			return -1
		case yNum:
			return 1
		default: // both alphanumeric – ASCII lexical
			if d := strings.Compare(x, y); d != 0 {
				return d
			}
		}
	}
	// All shared identifiers equal: the longer pre-release has higher precedence.
	switch {
	case len(ai) < len(bi):
		return -1
	case len(ai) > len(bi):
		return 1
	default:
		return 0
	}
}
