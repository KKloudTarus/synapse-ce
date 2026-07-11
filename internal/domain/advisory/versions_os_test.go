package advisory

import "testing"

// Each table is a known-correct ordering for the distro's native version algorithm; we assert the
// comparator's sign AND its antisymmetry. A separate ascending-chain test then checks transitivity.

func TestCompareDpkg(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"0", "1", -1},
		{"2.2.0", "2.2.28", -1},                    // numeric run compares by value, not lexically
		{"1.0~rc1", "1.0", -1},                     // '~' sorts before everything (pre-release)
		{"1.0~~", "1.0~~a", -1},                    // '~' chains
		{"1.0~~a", "1.0~", -1},                     //
		{"1.0~", "1.0", -1},                        //
		{"1.0", "1.0+b1", -1},                      // '+' sorts after end-of-part
		{"1.0", "1.0-1", -1},                       // missing revision is lowest
		{"1.0-1", "1.0-2", -1},                     // revision compared
		{"1:0", "9", 1},                            // epoch dominates
		{"1", "1a", -1},                            // trailing letter after a digit run
		{"1.0.0l-1~deb9u1", "1.0.0l-1~deb9u2", -1}, // real Debian point releases
		{"1.0.0l-1~deb9u1", "1.0.0l-1", -1},        // '~' in the revision
	}
	for _, c := range cases {
		if got := sign(compareDpkg(c.a, c.b)); got != c.want {
			t.Errorf("compareDpkg(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
		if got := sign(compareDpkg(c.b, c.a)); got != -c.want {
			t.Errorf("compareDpkg(%q,%q)=%d want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

func TestCompareApk(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.0.0", 0},            // missing trailing component == 0
		{"2.4.55-r0", "2.4.55-r1", -1}, // build revision
		{"1.2.3", "1.2.3-r1", -1},      // no revision == -r0 < -r1
		{"1.0", "1.0a", -1},            // trailing letter is newer
		{"1.0_alpha1", "1.0_alpha2", -1},
		{"1.0_alpha", "1.0_beta", -1},
		{"1.0_beta", "1.0_pre", -1},
		{"1.0_pre", "1.0_rc", -1},
		{"1.0_rc", "1.0", -1}, // pre-release suffix < plain release
		{"1.0", "1.0_p1", -1}, // post-release suffix > plain release
		{"1.0_rc1", "1.0_p1", -1},
		{"1.2.10", "1.2.9", 1},                 // numeric, not lexical
		{"1.0_alpha2", "1.0_alpha1_beta1", 1},  // stacked suffixes: the FIRST suffix (alpha2>alpha1) decides
		{"1.0_alpha1", "1.0_alpha1_beta1", 1},  // an extra trailing pre-release suffix is OLDER
		{"1.0_alpha1_beta1", "1.0_alpha1", -1}, // antisymmetric of the above
	}
	for _, c := range cases {
		if got := sign(compareApk(c.a, c.b)); got != c.want {
			t.Errorf("compareApk(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
		if got := sign(compareApk(c.b, c.a)); got != -c.want {
			t.Errorf("compareApk(%q,%q)=%d want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

func TestCompareRPM(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.0", "2.0", -1},
		{"2.0.1", "2.0.0", 1},
		{"1.0", "1.0.1", -1},
		{"1.0a", "1.0", 1},     // extra alpha segment is newer
		{"1.0~rc1", "1.0", -1}, // tilde pre-release
		{"1.0", "1.0^", -1},    // caret = snapshot after the bare version
		{"1.0^", "1.0.1", -1},
		{"2:1.0", "1:9.0", 1},              // epoch dominates
		{"3.1.6-7.el3", "3.1.6-8.el3", -1}, // release compared (real RHEL EVR tail)
		{"2:3.1.6-7.el3", "2:3.1.6-7.el3", 0},
		{"1.0", "1.0-1", -1}, // release present > absent
	}
	for _, c := range cases {
		if got := sign(compareRPM(c.a, c.b)); got != c.want {
			t.Errorf("compareRPM(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
		if got := sign(compareRPM(c.b, c.a)); got != -c.want {
			t.Errorf("compareRPM(%q,%q)=%d want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

// TestOSComparatorTransitivity: each ascending chain must stay strictly increasing under its
// comparator (a<b<c ⇒ a<c, no inversions), the belt-and-suspenders total-order check.
func TestOSComparatorTransitivity(t *testing.T) {
	chains := []struct {
		name    string
		compare func(a, b string) int
		asc     []string
	}{
		{"dpkg", compareDpkg, []string{"1.0~rc1", "1.0", "1.0-1", "1.0-2", "1.1", "2:0.1"}},
		{"apk", compareApk, []string{"1.0_alpha1", "1.0_rc", "1.0", "1.0a", "1.1-r0", "1.1-r2"}},
		{"rpm", compareRPM, []string{"1.0~rc1", "1.0", "1.0^", "1.0.1", "1.1-1", "1.1-2", "2:0.1"}},
	}
	for _, ch := range chains {
		for i := 0; i < len(ch.asc); i++ {
			for j := 0; j < len(ch.asc); j++ {
				want := sign(i - j)
				if got := sign(ch.compare(ch.asc[i], ch.asc[j])); got != want {
					t.Errorf("%s: compare(%q,%q)=%d want %d (chain order)", ch.name, ch.asc[i], ch.asc[j], got, want)
				}
			}
		}
	}
}

func TestOSValidFailsClosed(t *testing.T) {
	bad := []string{"", " 1.0", "1.0 ", "!:1.0"}
	for _, v := range bad {
		if validDpkg(v) {
			t.Errorf("validDpkg(%q) = true, want false (fail-closed)", v)
		}
	}
	// apk rejects unknown suffixes, trailing garbage, and ambiguous leading-zero components.
	for _, v := range []string{"", "1.0_foo", "1.0-x", "1.0.beta", "01.2", "1.0_alpha bad"} {
		if validApk(v) {
			t.Errorf("validApk(%q) = true, want false (fail-closed)", v)
		}
	}
	for _, v := range []string{"", "x:1.0", "---"} {
		if validRPM(v) {
			t.Errorf("validRPM(%q) = true, want false (fail-closed)", v)
		}
	}
	// sane versions validate
	for _, v := range []string{"1.0.0l-1~deb9u1", "1:2.3-4"} {
		if !validDpkg(v) {
			t.Errorf("validDpkg(%q) = false, want true", v)
		}
	}
	if !validApk("2.4.55-r0") || !validRPM("2:3.1.6-7.el3") {
		t.Error("a well-formed apk/rpm version must validate")
	}
}

// TestOSFamilySchemeDispatch: the release-versioned OSV ecosystem names route to the right comparator.
func TestOSFamilySchemeDispatch(t *testing.T) {
	cases := map[string]bool{
		"Debian:10":                          true,
		"Ubuntu:22.04:LTS":                   true,
		"Alpine:v3.18":                       true,
		"Red Hat:enterprise_linux:9::baseos": true,
		"Rocky Linux:8":                      true,
		"npm":                                false, // app ecosystem, not an OS family
		"Hex":                                false,
	}
	for eco, want := range cases {
		if _, ok := osFamilyScheme(eco); ok != want {
			t.Errorf("osFamilyScheme(%q) ok=%v want %v", eco, ok, want)
		}
	}
	// And end-to-end through schemeFor for an ECOSYSTEM range.
	if _, ok := schemeFor("Debian:10", "ECOSYSTEM"); !ok {
		t.Error("schemeFor(Debian:10, ECOSYSTEM) should resolve to the dpkg scheme")
	}
}

// TestAffectedDebianRange: an owned Debian advisory matches a vulnerable version below the fix and
// clears once patched – the end-to-end Epic B matching path (range ordering via the dpkg comparator).
func TestAffectedDebianRange(t *testing.T) {
	ranges := []Range{{
		Type:   "ECOSYSTEM",
		Events: []Event{{Introduced: "0"}, {Fixed: "1.1.0l-1~deb9u1"}},
	}}
	if !Affected("Debian:9", "1.1.0k-1", ranges, nil) {
		t.Error("a version below the fixed dpkg version must be affected")
	}
	if Affected("Debian:9", "1.1.0l-1~deb9u1", ranges, nil) {
		t.Error("the fixed version itself must NOT be affected (fixed is exclusive)")
	}
	if Affected("Debian:9", "1.1.0l-2", ranges, nil) {
		t.Error("a version above the fix must NOT be affected")
	}
}
