package advisory

import (
	"strconv"
	"strings"
)

// Fuzzy version ordering for CPE/NVD bounds. NVD product versions do NOT follow SemVer: they carry
// 4-part releases (9.0.62.1), qualifier tails (1.2.3.RELEASE, 3.0.0-M4, 8.5.0-rc1), and date-like
// forms (2021.01.05). Strict SemVer validation rejects all of these, so an otherwise-evaluable range
// gets skipped and the CVE is missed. This comparator recovers that recall WITHOUT inventing an order
// that would create a false positive: it orders by the leading NUMERIC segments first (the dominant,
// unambiguous signal), and only when two numeric cores are EQUAL does it consult the qualifier tail,
// where it classifies pre-release / release / post-release markers so a release is never ranked below
// itself (1.2.3.RELEASE == 1.2.3, 1.2.3-sp1 > 1.2.3, 3.0.0-M4 < 3.0.0), compares numeric qualifier
// suffixes numerically (rc10 > rc2), and treats an UNKNOWN qualifier as equal-to-release (never below)
// so an unrecognized tail cannot slip a version under a lower bound. Wildcard/placeholder versions
// (1.*, 1.x, 1-unknown) are NOT orderable, so such a bound still fails closed.

// preReleaseMarkers rank BELOW the bare release (Maven/SemVer pre-release vocabulary).
var preReleaseMarkers = map[string]bool{
	"alpha": true, "a": true, "beta": true, "b": true, "milestone": true, "m": true,
	"rc": true, "cr": true, "pre": true, "preview": true, "snapshot": true, "snap": true,
	"dev": true, "canary": true, "nightly": true, "ea": true, "pr": true,
}

// releaseMarkers are equivalent to the bare release (dropped, so 1.2.3.RELEASE == 1.2.3).
var releaseMarkers = map[string]bool{"release": true, "final": true, "ga": true, "stable": true}

// postReleaseMarkers rank ABOVE the bare release (service packs, patches, updates, builds).
var postReleaseMarkers = map[string]bool{
	"sp": true, "patch": true, "p": true, "u": true, "update": true, "fix": true,
	"hotfix": true, "rev": true, "revision": true, "build": true, "post": true,
}

// placeholderTokens make a version unorderable (a wildcard/placeholder bound must fail closed).
var placeholderTokens = map[string]bool{"x": true, "unknown": true, "na": true, "none": true, "tbd": true, "latest": true, "any": true, "star": true}

// OrderableFuzzy reports whether v can be fuzzy-ordered: it must begin with a numeric segment
// (optionally after a single leading v/V) and must not carry a wildcard or placeholder tail. Empty,
// "*", "-", "1.*", "1.x", "1-unknown", "latest" are not orderable, so a range bound like that is
// skipped (fail closed), never guessed.
func OrderableFuzzy(v string) bool {
	main, tail := splitFuzzy(v)
	if len(main) == 0 {
		return false
	}
	return tailOrderable(tail)
}

func tailOrderable(tail string) bool {
	if strings.ContainsAny(tail, "*?+") {
		return false
	}
	for _, tok := range tailTokens(tail) {
		if placeholderTokens[tok] {
			return false
		}
	}
	return true
}

// CompareFuzzy returns -1, 0, or 1 for a<b, a==b, a>b under the fuzzy ordering. It compares the
// leading numeric segments as integers (a missing trailing segment counts as 0, so 9.0.62.1 > 9.0.62),
// then, on an equal numeric core, orders by qualifier CLASS (pre-release < release == unknown < post-
// release) and, within the same class, by the tail's numeric-aware tokens. Callers should gate on
// OrderableFuzzy first; an unorderable operand compares as if it were bare "0".
func CompareFuzzy(a, b string) int {
	mainA, tailA := splitFuzzy(a)
	mainB, tailB := splitFuzzy(b)
	n := len(mainA)
	if len(mainB) > n {
		n = len(mainB)
	}
	for i := 0; i < n; i++ {
		if c := compareSegment(segAt(mainA, i), segAt(mainB, i)); c != 0 {
			return c
		}
	}
	// Numeric cores equal: order by qualifier class, then by the tail tokens within the class.
	rankA, tokA := classifyTail(tailA)
	rankB, tokB := classifyTail(tailB)
	if rankA != rankB {
		if rankA < rankB {
			return -1
		}
		return 1
	}
	return compareTokens(tokA, tokB)
}

// classifyTail returns the qualifier class (-1 pre-release, 0 release/unknown, +1 post-release) of a
// tail and the tokens that remain for an in-class tiebreak. A recognized release marker (RELEASE/GA/
// final/stable) is dropped so it compares equal to the bare release. An unknown alpha qualifier is
// class 0 (equal to release), never below it, so it cannot slip a version under a lower bound.
func classifyTail(tail string) (int, []string) {
	tokens := tailTokens(tail)
	if len(tokens) == 0 {
		return 0, nil
	}
	first := tokens[0]
	switch {
	case preReleaseMarkers[first]:
		return -1, tokens
	case postReleaseMarkers[first]:
		return 1, tokens[1:]
	case releaseMarkers[first]:
		return 0, tokens[1:]
	case isNumericToken(first):
		// A purely numeric tail after a non-dot separator (e.g. "1.2.3-1") reads as a build/revision
		// increment above the bare release.
		return 1, tokens
	default:
		return 0, tokens // unknown qualifier: equal-to-release class, kept only for a deterministic tiebreak
	}
}

// tailTokens lowercases the tail and splits it into maximal alphabetic / numeric runs, dropping all
// separators. "-rc10" -> [rc 10]; ".RELEASE" -> [release]; "-sp1" -> [sp 1].
func tailTokens(tail string) []string {
	tail = strings.ToLower(strings.TrimSpace(tail))
	var tokens []string
	i := 0
	for i < len(tail) {
		c := tail[i]
		switch {
		case c >= '0' && c <= '9':
			j := i
			for j < len(tail) && tail[j] >= '0' && tail[j] <= '9' {
				j++
			}
			tokens = append(tokens, tail[i:j])
			i = j
		case (c >= 'a' && c <= 'z'):
			j := i
			for j < len(tail) && tail[j] >= 'a' && tail[j] <= 'z' {
				j++
			}
			tokens = append(tokens, tail[i:j])
			i = j
		default:
			i++ // separator
		}
	}
	return tokens
}

func isNumericToken(tok string) bool {
	if tok == "" {
		return false
	}
	for i := 0; i < len(tok); i++ {
		if tok[i] < '0' || tok[i] > '9' {
			return false
		}
	}
	return true
}

// compareTokens orders two token sequences: numeric tokens compare numerically, a numeric token
// outranks an alphabetic one at the same position (rc2 > rc, i.e. more specific), alphabetic tokens
// compare lexically, and a missing trailing token is the smallest.
func compareTokens(a, b []string) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		ta, oka := tokenAt(a, i)
		tb, okb := tokenAt(b, i)
		if oka != okb { // one ran out: the shorter is smaller
			if !oka {
				return -1
			}
			return 1
		}
		na, numA := parseToken(ta)
		nb, numB := parseToken(tb)
		if numA && numB {
			if na != nb {
				if na < nb {
					return -1
				}
				return 1
			}
			continue
		}
		if numA != numB { // numeric outranks alphabetic at the same position
			if numA {
				return 1
			}
			return -1
		}
		if c := strings.Compare(ta, tb); c != 0 {
			return c
		}
	}
	return 0
}

func tokenAt(tokens []string, i int) (string, bool) {
	if i < len(tokens) {
		return tokens[i], true
	}
	return "", false
}

func parseToken(tok string) (int64, bool) {
	if !isNumericToken(tok) {
		return 0, false
	}
	n, err := strconv.ParseInt(tok, 10, 64)
	if err != nil {
		return 0, false // over-int64: treated as non-numeric, ordered lexically (rare, deterministic)
	}
	return n, true
}

// segment is one dot-separated numeric field of the version's numeric core. When the field fits an
// int64 it is compared numerically; an over-long run (beyond int64) falls back to a length-then-lexical
// compare so it never panics and stays deterministic.
type segment struct {
	num      int64
	overflow string // non-empty when the run did not fit int64
}

func segAt(segs []segment, i int) segment {
	if i < len(segs) {
		return segs[i]
	}
	return segment{} // missing trailing segment == 0
}

func compareSegment(a, b segment) int {
	if a.overflow == "" && b.overflow == "" {
		switch {
		case a.num < b.num:
			return -1
		case a.num > b.num:
			return 1
		default:
			return 0
		}
	}
	as, bs := a.overflow, b.overflow
	if as == "" {
		as = strconv.FormatInt(a.num, 10)
	}
	if bs == "" {
		bs = strconv.FormatInt(b.num, 10)
	}
	as, bs = strings.TrimLeft(as, "0"), strings.TrimLeft(bs, "0")
	if len(as) != len(bs) {
		if len(as) < len(bs) {
			return -1
		}
		return 1
	}
	return strings.Compare(as, bs)
}

// splitFuzzy parses v into its leading numeric core (dot-separated integer segments) and the remaining
// qualifier tail. A single leading v/V before a digit is stripped. Parsing stops at the first character
// that is neither a digit nor a dot separating two numeric fields; everything from there is the tail.
func splitFuzzy(v string) ([]segment, string) {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	var segs []segment
	i := 0
	for i < len(v) {
		if v[i] < '0' || v[i] > '9' {
			break
		}
		j := i
		for j < len(v) && v[j] >= '0' && v[j] <= '9' {
			j++
		}
		run := v[i:j]
		if n, err := strconv.ParseInt(run, 10, 64); err == nil {
			segs = append(segs, segment{num: n})
		} else {
			segs = append(segs, segment{overflow: run})
		}
		if j < len(v) && v[j] == '.' && j+1 < len(v) && v[j+1] >= '0' && v[j+1] <= '9' {
			i = j + 1
			continue
		}
		return segs, v[j:]
	}
	return segs, v[i:]
}
