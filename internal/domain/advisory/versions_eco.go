package advisory

import "strings"

// This file adds OWNED version comparators for the three ecosystems whose ECOSYSTEM-type ranges
// the matcher previously SKIPPED (schemeFor returned ok=false): Maven, RubyGems, NuGet. Each is a
// (compare, valid) pair plugged into schemeFor, so the owned advisory store can match RANGE
// advisories for these ecosystems offline – not just explicit-version advisories. Per golden
// rule 5, each `valid` FAILS CLOSED: a version it can't soundly order returns false → the range is
// skipped (never silently mis-ordered into a false match), exactly as before for unsupported input.

// ---- shared tokenizer -------------------------------------------------------

// splitVersionRuns tokenizes a version into maximal runs of ASCII digits and ASCII letters,
// dropping every separator (".", "-", "_", "+", …) – the scan RubyGems and Maven both use
// (Ruby: /[0-9]+|[a-z]+/i; Maven: digit/letter transitions act as separators). So "1.0.0.rc1"
// and "1.0.0-rc1" and "1.0.0rc1" all tokenize to ["1","0","0","rc","1"].
func splitVersionRuns(v string) []string {
	var out []string
	i, n := 0, len(v)
	for i < n {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
			j := i
			for j < n && v[j] >= '0' && v[j] <= '9' {
				j++
			}
			out = append(out, v[i:j])
			i = j
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			j := i
			for j < n && ((v[j] >= 'a' && v[j] <= 'z') || (v[j] >= 'A' && v[j] <= 'Z')) {
				j++
			}
			out = append(out, v[i:j])
			i = j
		default:
			i++ // separator
		}
	}
	return out
}

// validVersionChars reports whether v is non-empty and made only of version characters
// (alphanumerics + the separators. - _ +), i.e. nothing exotic the tokenizer would misread.
func validVersionChars(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	hasAlnum := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			hasAlnum = true
		case c == '.' || c == '-' || c == '_' || c == '+':
		default:
			return false
		}
	}
	return hasAlnum
}

// ---- RubyGems (Gem::Version) ------------------------------------------------

var rubygemsScheme = scheme{compare: compareRubyGems, valid: validVersionChars}

// compareRubyGems orders two Gem versions per Gem::Version#<=>: tokenize into segments, pad the
// shorter with numeric 0, then compare pairwise – numeric vs numeric numerically, string vs string
// lexically, and a STRING segment (a letter run = pre-release marker) is LOWER than a numeric one.
// So "1.0.0.a" < "1.0.0" and "1.0" == "1.0.0" (trailing zeros).
func compareRubyGems(a, b string) int {
	as, bs := splitVersionRuns(strings.ToLower(a)), splitVersionRuns(strings.ToLower(b))
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		x, y := "0", "0" // a missing trailing segment is numeric 0
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		xNum, yNum := isNumericStr(x), isNumericStr(y)
		switch {
		case xNum && yNum:
			if d := compareNumeric(x, y); d != 0 {
				return d
			}
		// A letter run is a pre-release segment → LOWER than a number (Gem::Version). NOTE this is
		// the OPPOSITE sign from SemVer §11 / comparePrerelease (where numeric identifiers are the
		// lower ones) – the two must not be "aligned".
		case xNum: // number > string
			return 1
		case yNum:
			return -1
		default:
			if d := strings.Compare(x, y); d != 0 {
				return d
			}
		}
	}
	return 0
}

// ---- NuGet (NuGetVersion) ---------------------------------------------------

var nugetScheme = scheme{compare: compareNuGet, valid: validNuGet}

// validNuGet accepts a NuGet version: a 1–4 segment numeric core (Major[.Minor[.Patch[.Revision]]])
// with an optional SemVer-style pre-release (after '-') and ignored build metadata (after '+').
func validNuGet(v string) bool {
	if !validVersionChars(v) {
		return false
	}
	core, _ := splitNuGet(v)
	if len(core) == 0 || len(core) > 4 {
		return false
	}
	for _, p := range core {
		if !isNumericStr(p) {
			return false
		}
	}
	return true
}

// splitNuGet returns the numeric core segments and the (lower-cased) pre-release string.
func splitNuGet(v string) ([]string, string) {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 { // drop build metadata
		v = v[:i]
	}
	pre := ""
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre = v[i+1:]
		v = v[:i]
	}
	if v == "" {
		return nil, pre
	}
	return strings.Split(v, "."), pre
}

// compareNuGet compares NuGet versions: the 4-segment numeric core (missing = 0) numerically, then
// SemVer pre-release precedence (a version WITHOUT a pre-release outranks one WITH; pre-releases
// compared per SemVer §11, case-insensitively).
func compareNuGet(a, b string) int {
	ac, ap := splitNuGet(a)
	bc, bp := splitNuGet(b)
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
	switch {
	case ap == "" && bp == "":
		return 0
	case ap == "":
		return 1
	case bp == "":
		return -1
	}
	return comparePrerelease(ap, bp)
}

// ---- Maven (ComparableVersion) ----------------------------------------------

var mavenScheme = scheme{compare: compareMaven, valid: validMaven}

// validMaven requires a numeric leading segment (a real Maven release/version always starts with a
// number, e.g. "1", "2.5.1", "32.1.3-jre"). This is the fail-closed gate: a qualifier-only or
// non-numeric-leading string is skipped rather than guessed.
func validMaven(v string) bool {
	if !validVersionChars(v) {
		return false
	}
	t := splitVersionRuns(strings.ToLower(v))
	return len(t) > 0 && isNumericStr(t[0])
}

// mavenQualifierRank maps a Maven qualifier to its order relative to the release ("") at rank 5,
// following Apache Maven's ComparableVersion: alpha<beta<milestone<rc<snapshot < release < sp, with
// the common aliases. An UNKNOWN qualifier sorts AFTER all known ones (rank 7) and is then ordered
// lexically among unknowns – matching Maven, where an unrecognized qualifier outranks the release.
func mavenQualifierRank(q string) int {
	switch q {
	case "alpha", "a":
		return 0
	case "beta", "b":
		return 1
	case "milestone", "m":
		return 2
	case "rc", "cr":
		return 3
	case "snapshot":
		return 4
	case "", "ga", "final", "release":
		return 5
	case "sp":
		return 6
	default:
		return 7 // unknown qualifier > release; ties broken lexically (see compareMavenItem)
	}
}

// compareMaven orders two Maven versions. It compares the tokenized item lists left to right; the
// numeric core (the dominant signal) is exact, and the qualifier tie-break follows Maven's
// canonical qualifier ordering. NOTE: it treats '-' and '.' uniformly (a flat token list) rather
// than reproducing ComparableVersion's '-' sub-list NESTING; the numeric-core comparison is
// unaffected, so range membership is correct for the overwhelming majority of real versions – the
// nesting only perturbs exotic equal-core tie-breaks (e.g. "1-1" vs "1.1").
func compareMaven(a, b string) int {
	as, bs := splitVersionRuns(strings.ToLower(a)), splitVersionRuns(strings.ToLower(b))
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		x, xok := itemAt(as, i)
		y, yok := itemAt(bs, i)
		if d := compareMavenItem(x, xok, y, yok); d != 0 {
			return d
		}
	}
	return 0
}

// itemAt returns the i-th token and whether it exists; a missing token is Maven's "null".
func itemAt(s []string, i int) (string, bool) {
	if i < len(s) {
		return s[i], true
	}
	return "", false
}

// compareMavenItem compares one position. A MISSING item (ok=false) is Maven's "null": vs a number
// it is 0 (so trailing ".0" is equal – "1.0" == "1"); vs a qualifier it is the RELEASE qualifier (so
// "1-alpha" < "1" and "1-sp"/"1-foo" > "1"). A number always outranks a qualifier (IntItem > StringItem).
func compareMavenItem(a string, aok bool, b string, bok bool) int {
	aNum := aok && isNumericStr(a)
	bNum := bok && isNumericStr(b)
	switch {
	case !aok && !bok:
		return 0
	case !aok: // missing vs present b
		if bNum {
			return -compareNumeric(b, "0") // missing(0) vs number
		}
		return -compareQualToRelease(b) // missing(release) vs qualifier
	case !bok: // present a vs missing
		if aNum {
			return compareNumeric(a, "0")
		}
		return compareQualToRelease(a)
	case aNum && bNum:
		return compareNumeric(a, b)
	case aNum: // number > qualifier (b is a qualifier here, since bNum is false)
		return 1
	case bNum:
		return -1
	default: // both qualifiers
		ra, rb := mavenQualifierRank(a), mavenQualifierRank(b)
		if ra != rb {
			if ra < rb {
				return -1
			}
			return 1
		}
		if ra == 7 { // both unknown qualifiers – lexical
			return strings.Compare(a, b)
		}
		return 0
	}
}

// compareQualToRelease compares a qualifier to the release (rank 5): pre-release qualifiers are
// negative, sp/unknown positive.
func compareQualToRelease(q string) int {
	switch r := mavenQualifierRank(q); {
	case r < 5:
		return -1
	case r > 5:
		return 1
	default:
		return 0
	}
}
