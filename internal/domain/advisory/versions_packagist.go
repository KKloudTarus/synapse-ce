package advisory

import (
	"regexp"
	"strconv"
	"strings"
)

// ---- Packagist (Composer) ----------------------------------------------------
//
// Composer versions are SemVer-like but order their stability suffixes differently from SemVer §11:
// dev < alpha < beta < RC < stable < patch, and the suffix keyword aliases (a/alpha, b/beta, rc/RC,
// p/pl/patch) sort by that fixed stability rank, NOT alphabetically. Reusing the plain SemVer engine would
// mis-order a pre-release advisory boundary (SemVer would sort "RC" before "alpha" because 'R' < 'a'), so
// Packagist gets its own comparator. It stays FAIL-CLOSED: a version that is not a numeric core plus an
// optional recognized stability suffix (a branch alias like `dev-master`, a git ref) is rejected by
// validPackagist, and the range is then skipped rather than lexically guessed (EPIC #1034, #1037).

var packagistScheme = scheme{compare: comparePackagist, valid: validPackagist}

// packagistRE matches a Composer release version: a 1–4 segment numeric core, an optional stability suffix
// (keyword + optional number), and ignored build metadata. Separators between core and suffix may be
// `.`/`-`/`_` or absent (`1.0.0RC1`). It is anchored so a branch alias (`dev-master`, `1.x-dev`) does not
// match and is fail-closed.
var packagistRE = regexp.MustCompile(`^v?(\d+(?:\.\d+){0,3})(?:[._-]?(stable|dev|beta|b|rc|alpha|a|patch|pl|p)\.?(\d+)?)?$`)

// packagistStability ranks the stability keywords from lowest to highest precedence. A missing suffix is a
// stable release (rank 4), which outranks every pre-release and is outranked by a patch release.
var packagistStability = map[string]int{
	"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "rc": 3, "stable": 4, "patch": 5, "pl": 5, "p": 5,
}

// splitPackagist parses a Composer version into its numeric core segments, its stability rank, and the
// stability suffix number. ok=false for a version that does not match the release grammar.
func splitPackagist(v string) (core []string, stability, suffixNum int, ok bool) {
	v = strings.TrimSpace(strings.ToLower(v))
	if i := strings.IndexByte(v, '+'); i >= 0 { // drop build metadata
		v = v[:i]
	}
	m := packagistRE.FindStringSubmatch(v)
	if m == nil {
		return nil, 0, 0, false
	}
	core = strings.Split(m[1], ".")
	stability = 4 // no suffix -> stable
	if m[2] != "" {
		r, known := packagistStability[m[2]]
		if !known {
			return nil, 0, 0, false
		}
		stability = r
	}
	if m[3] != "" && stability != 4 {
		// A number is meaningful for a pre-release/patch suffix (alpha1, rc2, p3) but NOT for `stable`:
		// Composer normalizes `1.0.0-stable7` back to the plain `1.0.0` release, so the number is ignored
		// there (else `1.0.0` would order below `1.0.0-stable1`, a false range hit).
		n, err := strconv.Atoi(m[3])
		if err != nil {
			return nil, 0, 0, false
		}
		suffixNum = n
	}
	return core, stability, suffixNum, true
}

// validPackagist reports whether v is an orderable Composer release version.
func validPackagist(v string) bool {
	_, _, _, ok := splitPackagist(v)
	return ok
}

// comparePackagist orders two Composer versions: the 4-segment numeric core (missing = 0) numerically, then
// the stability rank (dev<alpha<beta<RC<stable<patch), then the suffix number numerically.
func comparePackagist(a, b string) int {
	ac, as, an, aok := splitPackagist(a)
	bc, bs, bn, bok := splitPackagist(b)
	if !aok || !bok {
		// Defensive: the matcher gates on validPackagist, so this is unreachable in production. Order by
		// parseability only (never lexically, per the #1037 no-lexical-fallback bar): an unparseable version
		// sorts below any parseable one, and two unparseable versions are equal. This keeps compare a total,
		// transitive order without guessing a version order it cannot justify.
		switch {
		case !aok && !bok:
			return 0
		case !aok:
			return -1
		default:
			return 1
		}
	}
	for i := 0; i < 4; i++ {
		x, y := "0", "0"
		if i < len(ac) {
			x = ac[i]
		}
		if i < len(bc) {
			y = bc[i]
		}
		if d := compareNumeric(x, y); d != 0 {
			return d
		}
	}
	if as != bs {
		if as < bs {
			return -1
		}
		return 1
	}
	if an != bn {
		if an < bn {
			return -1
		}
		return 1
	}
	return 0
}
