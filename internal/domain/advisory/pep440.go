package advisory

import (
	"regexp"
	"strings"
)

// This file is the PyPI version comparator (PEP 440), the per-ecosystem ordering the SemVer comparator can't
// express: PyPI versions carry an epoch (`1!2.0`), implicit/explicit post-releases (`1.0.post1`, `1.0-1`),
// pre-releases (`1.0a1`, `1.0rc2`), and dev-releases (`1.0.dev3`) whose precedence is dev < pre < final <
// post – none of which SemVer 2.0 orders correctly. It is pure + table-tested against the PEP 440 spec
// examples, so an OSV ECOSYSTEM-range verdict on a PyPI advisory is deterministic + third-party-free.
//
// Submatch groups: 1=epoch 2=release 3=pre-letter 4=pre-num 5=implicit-post(-N) 6=post-letter 7=post-num
// 8=dev-letter 9=dev-num. Local versions (+...) are tolerated but ignored for precedence (advisory bounds
// don't use them). Longer pre/post keywords are ordered first in the alternation so e.g. "alpha" is not
// split as "a"+"lpha".
var pep440RE = regexp.MustCompile(`(?i)^\s*v?(?:([0-9]+)!)?([0-9]+(?:\.[0-9]+)*)` +
	`(?:[-_.]?(alpha|beta|preview|pre|rc|a|b|c)[-_.]?([0-9]+)?)?` +
	`(?:(?:-([0-9]+))|(?:[-_.]?(post|rev|r)[-_.]?([0-9]+)?))?` +
	`(?:[-_.]?(dev)[-_.]?([0-9]+)?)?` +
	`(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?\s*$`)

// pep is a parsed PEP 440 version reduced to the fields that drive ordering.
type pep struct {
	epoch   string   // numeric string (default "0")
	release []string // numeric release segments
	hasPre  bool
	preL    string // normalized pre letter: "a" | "b" | "rc"
	preN    string // pre number (default "0")
	hasPost bool
	postN   string // post number (default "0")
	hasDev  bool
	devN    string // dev number (default "0")
}

// validPEP440 reports whether v is a well-formed PEP 440 version – the fail-closed gate the matcher uses
// before trusting comparePEP440 (a non-PEP-440 token like "latest" or "1.2.x" must never match a range).
func validPEP440(v string) bool { return pep440RE.MatchString(v) }

func parsePEP440(v string) (pep, bool) {
	m := pep440RE.FindStringSubmatch(v)
	if m == nil {
		return pep{}, false
	}
	p := pep{epoch: "0", release: strings.Split(m[2], ".")}
	if m[1] != "" {
		p.epoch = m[1]
	}
	if m[3] != "" {
		p.hasPre, p.preL, p.preN = true, normalizePreLetter(m[3]), defaultZero(m[4])
	}
	switch {
	case m[5] != "": // implicit post-release "-N"
		p.hasPost, p.postN = true, m[5]
	case m[6] != "": // explicit post/rev/r
		p.hasPost, p.postN = true, defaultZero(m[7])
	}
	if m[8] != "" {
		p.hasDev, p.devN = true, defaultZero(m[9])
	}
	return p, true
}

// normalizePreLetter folds PEP 440 pre-release spellings to a/b/rc so they order lexically (a < b < rc).
func normalizePreLetter(s string) string {
	switch strings.ToLower(s) {
	case "alpha", "a":
		return "a"
	case "beta", "b":
		return "b"
	case "c", "rc", "pre", "preview":
		return "rc"
	}
	return strings.ToLower(s)
}

func defaultZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

// comparePEP440 orders two PEP 440 versions (-1/0/+1). Both are assumed valid (validPEP440 gates the
// matcher); an unparseable input falls back to a lexical compare so this never panics. Precedence follows
// PEP 440 / the packaging library's cmpkey: epoch, then release, then the pre/post/dev phases where a
// dev-release sorts below a pre-release below the final release below a post-release.
func comparePEP440(a, b string) int {
	pa, oka := parsePEP440(a)
	pb, okb := parsePEP440(b)
	if !oka || !okb {
		return strings.Compare(a, b)
	}
	if d := compareNumeric(pa.epoch, pb.epoch); d != 0 {
		return d
	}
	if d := compareRelease(pa.release, pb.release); d != 0 {
		return d
	}
	if d := comparePre(pa, pb); d != 0 {
		return d
	}
	if d := comparePost(pa, pb); d != 0 {
		return d
	}
	return compareDev(pa, pb)
}

// compareRelease compares two release segment lists numerically; a missing trailing segment is 0, so
// "1.0" == "1.0.0".
func compareRelease(a, b []string) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		x, y := "0", "0"
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if d := compareNumeric(x, y); d != 0 {
			return d
		}
	}
	return 0
}

// prePhase ranks the pre component: -1 = "before pre-releases" (a dev-release of a final with no pre, which
// PEP 440 sorts below any pre-release), 0 = a real pre-release, +1 = "after pre-releases" (no pre-release).
func prePhase(p pep) int {
	switch {
	case p.hasPre:
		return 0
	case !p.hasPost && p.hasDev:
		return -1
	default:
		return 1
	}
}

func comparePre(a, b pep) int {
	if d := cmpInt(prePhase(a), prePhase(b)); d != 0 {
		return d
	}
	if !a.hasPre { // both NEG_INF or both POS_INF – equal in this phase
		return 0
	}
	if a.preL != b.preL {
		return strings.Compare(a.preL, b.preL)
	}
	return compareNumeric(a.preN, b.preN)
}

// comparePost: a version with no post-release sorts BELOW one with a post (PEP 440 NEG_INF).
func comparePost(a, b pep) int {
	if a.hasPost != b.hasPost {
		return boolHigher(a.hasPost)
	}
	if !a.hasPost {
		return 0
	}
	return compareNumeric(a.postN, b.postN)
}

// compareDev: a version with no dev-release sorts ABOVE one with a dev (PEP 440 POS_INF).
func compareDev(a, b pep) int {
	if a.hasDev != b.hasDev {
		return boolHigher(b.hasDev) // the one WITHOUT dev is higher
	}
	if !a.hasDev {
		return 0
	}
	return compareNumeric(a.devN, b.devN)
}

// boolHigher returns +1 if aHas (the left side has the component and so is higher), else -1.
func boolHigher(aHas bool) int {
	if aHas {
		return 1
	}
	return -1
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
