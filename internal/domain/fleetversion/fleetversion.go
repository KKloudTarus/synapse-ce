// Package fleetversion is the pure-domain version model for fleet agent/control-plane version skew
// (#412, epic #405). It parses and orders "major.minor.patch" versions (an optional leading "v" and
// any pre-release/build metadata after the numeric core are ignored for ordering — a conservative
// core-only comparison) and answers "does this version meet a minimum floor". It imports only stdlib.
package fleetversion

import (
	"strconv"
	"strings"
)

// Version is a parsed numeric version core (major.minor.patch).
type Version struct {
	Major int
	Minor int
	Patch int
}

// Parse parses "v1.2.3" / "1.2.3" / "1.2" / "1" (missing components default to 0), ignoring any
// pre-release/build suffix ("-rc1", "+meta"). ok is false when the numeric core is absent or not a
// non-negative integer triple.
func Parse(s string) (Version, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	if s == "" {
		return Version{}, false
	}
	// Cut pre-release/build metadata: the core ends at the first '-' or '+'.
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return Version{}, false
	}
	nums := make([]int, 3)
	for i, p := range parts {
		if p == "" {
			return Version{}, false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return Version{}, false
		}
		nums[i] = n
	}
	return Version{Major: nums[0], Minor: nums[1], Patch: nums[2]}, true
}

// Compare returns -1 if v < o, 0 if equal, +1 if v > o.
func (v Version) Compare(o Version) int {
	switch {
	case v.Major != o.Major:
		return sign(v.Major - o.Major)
	case v.Minor != o.Minor:
		return sign(v.Minor - o.Minor)
	case v.Patch != o.Patch:
		return sign(v.Patch - o.Patch)
	default:
		return 0
	}
}

// Less reports whether v is strictly older than o.
func (v Version) Less(o Version) bool { return v.Compare(o) < 0 }

// String renders the canonical "major.minor.patch".
func (v Version) String() string {
	return strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) + "." + strconv.Itoa(v.Patch)
}

// MeetsFloor reports whether version satisfies the minimum floor.
//
//   - An EMPTY floor means "no floor" — always true (the feature is off).
//   - An UNPARSEABLE floor is treated as no floor (true): an operator's malformed floor must not brick
//     the whole fleet by refusing every agent; a misconfigured floor is a config problem to surface,
//     not a reason to deny service.
//   - A parseable floor with an UNPARSEABLE version FAILS CLOSED (false): under an active floor, an
//     agent that will not state a valid version is treated as below it, not waved through.
func MeetsFloor(version, floor string) bool {
	floor = strings.TrimSpace(floor)
	if floor == "" {
		return true
	}
	fv, ok := Parse(floor)
	if !ok {
		return true // malformed floor => no enforceable floor (availability over a config typo)
	}
	vv, ok := Parse(version)
	if !ok {
		return false // active floor + unparseable client version => refuse (fail closed)
	}
	return vv.Compare(fv) >= 0
}

func sign(n int) int {
	if n < 0 {
		return -1
	}
	return 1
}
