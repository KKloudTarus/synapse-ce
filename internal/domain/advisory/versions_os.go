package advisory

import "strings"

// This file adds OWNED version comparators for the THREE OS-package families whose ECOSYSTEM-type
// ranges the matcher previously SKIPPED (schemeFor returned ok=false): Debian/Ubuntu (dpkg), Alpine
// (apk), and the RPM distros (rpm). Each is a faithful port of the distro's native package-version
// ordering, plugged into schemeFor via osFamilyScheme, so the owned advisory store can match RANGE
// advisories for OS packages offline – detection independence for container/OS scans (Epic B).
//
// every `valid` FAILS CLOSED: a version it cannot soundly order returns false → the
// range is skipped (never mis-ordered into a false match), exactly as for any unsupported input.

// osFamilyScheme maps an OSV distro ECOSYSTEM to its native ordering. OSV names distro ecosystems with
// a release suffix ("Debian:10", "Alpine:v3.18", "Red Hat:enterprise_linux:9::baseos"); the family is
// the segment before the first ':'. dpkg orders Debian/Ubuntu, apk orders Alpine (+ apk-based Wolfi/
// Chainguard), rpm orders the RPM distros. An unknown family returns ok=false (range skipped).
func osFamilyScheme(ecosystem string) (scheme, bool) {
	family := ecosystem
	if i := strings.IndexByte(ecosystem, ':'); i >= 0 {
		family = ecosystem[:i]
	}
	switch family {
	case "Debian", "Ubuntu":
		return dpkgScheme, true
	case "Alpine", "Wolfi", "Chainguard":
		return apkScheme, true
	case "Red Hat", "Rocky Linux", "AlmaLinux", "openSUSE", "SUSE", "Fedora", "Mageia", "Oracle Linux":
		return rpmScheme, true
	}
	return scheme{}, false
}

var (
	dpkgScheme = scheme{compare: compareDpkg, valid: validDpkg}
	apkScheme  = scheme{compare: compareApk, valid: validApk}
	rpmScheme  = scheme{compare: compareRPM, valid: validRPM}
)

// ---- small byte helpers (local to this file) --------------------------------

// signum normalizes any int to -1/0/1 (the comparator contract). (`sign` is defined in a test file.)
func signum(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

func isDigitB(c byte) bool { return c >= '0' && c <= '9' }
func isAlphaB(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isAlnumB(c byte) bool { return isDigitB(c) || isAlphaB(c) }

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigitB(s[i]) {
			return false
		}
	}
	return true
}

// compareNumericStr compares two non-negative integer strings by value (leading zeros ignored):
// longer (after trimming zeros) wins, else lexical. Shared by dpkg/rpm epoch + numeric segments.
func compareNumericStr(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return signum(len(a) - len(b))
	}
	return signum(strings.Compare(a, b))
}

// ======================= Debian / Ubuntu (dpkg) =============================

// compareDpkg orders two Debian/Ubuntu package versions per Debian Policy §5.6.12 (the dpkg
// algorithm): epoch (numeric, default 0) then upstream-version then debian-revision, each compared by
// verrevcmp where '~' sorts before everything (so 1.0~rc1 < 1.0), letters sort before non-letters, and
// maximal digit runs compare numerically.
func compareDpkg(a, b string) int {
	ea, ua, ra := splitDebian(a)
	eb, ub, rb := splitDebian(b)
	if c := compareNumericStr(ea, eb); c != 0 {
		return c
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

// splitDebian splits "[epoch:]upstream[-revision]" → (epoch, upstream, revision). Epoch defaults to
// "0"; a missing revision is "" (verrevcmp treats it as the lowest, so 1.0 < 1.0-1).
func splitDebian(v string) (epoch, upstream, revision string) {
	epoch = "0"
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch, v = v[:i], v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		upstream, revision = v[:i], v[i+1:]
	} else {
		upstream = v
	}
	return epoch, upstream, revision
}

// dpkgOrder ranks a byte for the non-digit phase: '~' is below everything (even end-of-part), letters
// keep their ASCII value, every other char sorts above letters. Digits never reach here.
func dpkgOrder(c byte) int {
	switch {
	case isAlphaB(c):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

// verrevcmp compares one dpkg version part (upstream or revision) – the canonical dpkg algorithm.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// non-digit run: compare by dpkgOrder; end-of-part ranks as 0 (so a trailing '~' loses).
		for (i < len(a) && !isDigitB(a[i])) || (j < len(b) && !isDigitB(b[j])) {
			ac, bc := 0, 0
			if i < len(a) {
				ac = dpkgOrder(a[i])
			}
			if j < len(b) {
				bc = dpkgOrder(b[j])
			}
			if ac != bc {
				return signum(ac - bc)
			}
			i++
			j++
		}
		// digit run: skip leading zeros, then a longer run is larger, else first differing digit decides.
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		firstDiff := 0
		for i < len(a) && isDigitB(a[i]) && j < len(b) && isDigitB(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigitB(a[i]) {
			return 1
		}
		if j < len(b) && isDigitB(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return signum(firstDiff)
		}
	}
	return 0
}

// validDpkg fails closed: epoch (if present) must be digits, the upstream part must be non-empty, and
// every char must be in the dpkg-allowed set so verrevcmp orders only well-formed versions.
func validDpkg(v string) bool {
	if strings.TrimSpace(v) != v || v == "" {
		return false
	}
	e, u, r := splitDebian(v)
	if !allDigits(e) || u == "" {
		return false
	}
	for _, part := range [2]string{u, r} {
		for i := 0; i < len(part); i++ {
			c := part[i]
			if !isAlnumB(c) && c != '.' && c != '+' && c != '~' && c != ':' {
				return false
			}
		}
	}
	return true
}

// ============================== Alpine (apk) ================================

// apkSuffixRank ranks an apk pre/post-release suffix relative to "no suffix" (rank 4): the pre-release
// suffixes sort below a plain release, the post-release ones above (apk-tools src/version.c).
var apkSuffixRank = map[string]int{
	"alpha": 0, "beta": 1, "pre": 2, "rc": 3,
	"cvs": 5, "svn": 6, "git": 7, "hg": 8, "p": 9,
}

// apkSuffix is one "_<name><num>" suffix token (rank from apkSuffixRank, optional number).
type apkSuffix struct{ rank, num int }

const apkNoSuffixRank = 4 // a missing suffix ranks as a plain release (between pre- and post-release)

type apkVersion struct {
	nums     []int       // dot-separated numeric components
	letter   byte        // trailing single letter (0 if none)
	suffixes []apkSuffix // stacked "_suffix" tokens, in order (apk compares them left-to-right)
	rev      int         // -r<revision> build number (0 if none)
}

// compareApk orders two Alpine apk versions: numeric components, then a trailing letter, then the
// pre/post-release suffix tokens left-to-right, then the -r build revision (apk-tools ordering). A
// missing suffix at a position ranks as a plain release, so a trailing pre-release suffix makes a
// version older and a post-release suffix makes it newer. Versions outside validApk never reach here.
func compareApk(a, b string) int {
	va, oka := parseApk(a)
	vb, okb := parseApk(b)
	if !oka || !okb { // defensive: valid() gates this, but never mis-order on a parse miss
		return 0
	}
	n := max(len(va.nums), len(vb.nums))
	for k := 0; k < n; k++ {
		x, y := 0, 0
		if k < len(va.nums) {
			x = va.nums[k]
		}
		if k < len(vb.nums) {
			y = vb.nums[k]
		}
		if x != y {
			return signum(x - y)
		}
	}
	if va.letter != vb.letter {
		return signum(int(va.letter) - int(vb.letter))
	}
	ns := max(len(va.suffixes), len(vb.suffixes))
	for k := 0; k < ns; k++ {
		ra, na := apkNoSuffixRank, 0
		if k < len(va.suffixes) {
			ra, na = va.suffixes[k].rank, va.suffixes[k].num
		}
		rb, nb := apkNoSuffixRank, 0
		if k < len(vb.suffixes) {
			rb, nb = vb.suffixes[k].rank, vb.suffixes[k].num
		}
		if ra != rb {
			return signum(ra - rb)
		}
		if na != nb {
			return signum(na - nb)
		}
	}
	return signum(va.rev - vb.rev)
}

// parseApk parses the supported apk grammar:
//
//	NUM('.'NUM)* LETTER? ('_' SUFFIX NUM?)* ('-r' NUM)?
//
// returning ok=false on anything outside it (so the range is skipped, never mis-ordered). Stacked
// suffixes are kept IN ORDER and compared left-to-right (apk-tools semantics). Numeric components with
// a redundant leading zero are rejected (apk's leading-zero "fractional" semantics are ambiguous to
// order; failing closed is safer than guessing).
func parseApk(v string) (apkVersion, bool) {
	var out apkVersion
	i := 0
	readNum := func() (int, bool) {
		s := i
		for i < len(v) && isDigitB(v[i]) {
			i++
		}
		if i == s {
			return 0, false
		}
		run := v[s:i]
		if len(run) > 1 && run[0] == '0' {
			return 0, false // ambiguous leading-zero component
		}
		return atoiBounded(run)
	}
	first, ok := readNum()
	if !ok {
		return out, false
	}
	out.nums = append(out.nums, first)
	for i < len(v) && v[i] == '.' {
		i++
		n, ok := readNum()
		if !ok {
			return out, false
		}
		out.nums = append(out.nums, n)
	}
	if i < len(v) && isAlphaB(v[i]) { // optional single trailing letter
		out.letter = lower(v[i])
		i++
	}
	for i < len(v) && v[i] == '_' { // stacked "_suffix[num]" tokens, kept in order
		i++
		s := i
		for i < len(v) && isAlphaB(v[i]) {
			i++
		}
		rank, known := apkSuffixRank[strings.ToLower(v[s:i])]
		if !known {
			return out, false
		}
		suf := apkSuffix{rank: rank}
		if num, ok := readNum(); ok {
			suf.num = num
		}
		out.suffixes = append(out.suffixes, suf)
	}
	if strings.HasPrefix(v[i:], "-r") { // optional build revision
		i += 2
		n, ok := readNum()
		if !ok {
			return out, false
		}
		out.rev = n
	}
	if i != len(v) { // trailing garbage ⇒ cannot order soundly
		return out, false
	}
	return out, true
}

func validApk(v string) bool {
	if strings.TrimSpace(v) != v {
		return false
	}
	_, ok := parseApk(v)
	return ok
}

// ============================ RPM distros (rpm) =============================

// compareRPM orders two RPM versions: EVR = "[epoch:]version[-release]"; epoch is numeric (default 0),
// version and release are each compared by rpmvercmp (rpm's lib/rpmvercmp.c, incl. '~' and '^').
func compareRPM(a, b string) int {
	ea, va, ra := splitEVR(a)
	eb, vb, rb := splitEVR(b)
	if c := compareNumericStr(ea, eb); c != 0 {
		return c
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c
	}
	return rpmvercmp(ra, rb)
}

// splitEVR splits "[epoch:]version[-release]". rpm forbids '-' inside version/release, so the first '-'
// separates them. Epoch defaults to "0"; a missing release is "".
func splitEVR(s string) (epoch, version, release string) {
	epoch = "0"
	if i := strings.IndexByte(s, ':'); i >= 0 {
		epoch, s = s[:i], s[i+1:]
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		version, release = s[:i], s[i+1:]
	} else {
		version = s
	}
	return epoch, version, release
}

// rpmvercmp is a faithful port of rpm's lib/rpmvercmp.c. It walks both strings dropping separators,
// honours '~' (sorts before everything) and '^' (sorts after the bare prefix), then compares maximal
// all-digit or all-alpha segments: numeric segments compare by value and outrank alpha segments.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnumB(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnumB(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		// '~' sorts before everything, including the end of the string.
		aT := i < len(a) && a[i] == '~'
		bT := j < len(b) && b[j] == '~'
		if aT || bT {
			if !aT {
				return 1
			}
			if !bT {
				return -1
			}
			i++
			j++
			continue
		}
		// '^' sorts after the bare prefix (so 1.0 < 1.0^ < 1.0.1).
		aC := i < len(a) && a[i] == '^'
		bC := j < len(b) && b[j] == '^'
		if aC || bC {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if !aC {
				return 1
			}
			if !bC {
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		startI, startJ := i, j
		isNum := isDigitB(a[i])
		if isNum {
			for i < len(a) && isDigitB(a[i]) {
				i++
			}
			for j < len(b) && isDigitB(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlphaB(a[i]) {
				i++
			}
			for j < len(b) && isAlphaB(b[j]) {
				j++
			}
		}
		segA, segB := a[startI:i], b[startJ:j]
		if len(segB) == 0 {
			// b's segment is the other type (or absent): a numeric segment outranks an alpha one.
			if isNum {
				return 1
			}
			return -1
		}
		if isNum {
			if c := compareNumericStr(segA, segB); c != 0 {
				return c
			}
		} else if c := strings.Compare(segA, segB); c != 0 {
			return signum(c)
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	default:
		return 1
	}
}

// validRPM fails closed: epoch (if present) must be digits and the version part must contain at least
// one alphanumeric (rpmvercmp orders by alnum segments – a separator-only version is meaningless).
func validRPM(v string) bool {
	if strings.TrimSpace(v) != v || v == "" {
		return false
	}
	e, ver, _ := splitEVR(v)
	if !allDigits(e) || ver == "" {
		return false
	}
	for i := 0; i < len(ver); i++ {
		if isAlnumB(ver[i]) {
			return true
		}
	}
	return false
}

// ---- shared small helpers ---------------------------------------------------

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// atoiBounded parses a non-negative integer, capping absurdly long runs (>9 digits) to avoid overflow;
// such a component is rejected (ok=false) rather than wrapped.
func atoiBounded(s string) (int, bool) {
	if len(s) == 0 || len(s) > 9 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if !isDigitB(s[i]) {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}
