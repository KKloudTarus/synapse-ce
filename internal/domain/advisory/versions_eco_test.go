package advisory

import "testing"

// sign normalizes a comparator result to -1/0/1 for table assertions.
func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

func TestCompareRubyGems(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0.0", 0},      // trailing zeros
		{"1.0.0", "1.1.0", -1},   // minor
		{"2.0.0", "1.9.9", 1},    // major dominates
		{"1.0.0.a", "1.0.0", -1}, // letter segment = pre-release, lower
		{"1.0.0.alpha", "1.0.0.beta", -1},
		{"1.0.0.beta", "1.0.0.rc", -1}, // lexical among strings
		{"1.0.0.beta.1", "1.0.0.beta.2", -1},
		{"1.2.3", "1.2.3", 0},
		{"1.0.0.pre", "1.0.0", -1},
	}
	for _, c := range cases {
		if got := sign(compareRubyGems(c.a, c.b)); got != c.want {
			t.Errorf("compareRubyGems(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
		if got := sign(compareRubyGems(c.b, c.a)); got != -c.want { // antisymmetry
			t.Errorf("compareRubyGems(%q,%q)=%d want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

func TestCompareNuGet(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0", 0},
		{"1.0.0.0", "1.0.0", 0}, // 4th revision segment, zero
		{"1.0.0.1", "1.0.0", 1}, // 4th revision
		{"1.0.1", "1.0.0", 1},
		{"2.0.0", "1.9.9", 1},
		{"1.0.0-alpha", "1.0.0", -1}, // pre-release < release
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-rc.1", "1.0.0-rc.2", -1},
		{"1.0.0+build", "1.0.0", 0},       // build metadata ignored
		{"1.0.0-Alpha", "1.0.0-alpha", 0}, // case-insensitive
		{"1.0.0", "1.0.0", 0},
	}
	for _, c := range cases {
		if got := sign(compareNuGet(c.a, c.b)); got != c.want {
			t.Errorf("compareNuGet(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
		if got := sign(compareNuGet(c.b, c.a)); got != -c.want {
			t.Errorf("compareNuGet(%q,%q)=%d want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

func TestCompareMaven(t *testing.T) {
	// Canonical Apache Maven ComparableVersion orderings (the qualifier ladder + unknown-qualifier rule).
	cases := []struct {
		a, b string
		want int
	}{
		{"1", "1.0", 0}, {"1", "1.0.0", 0}, {"1.0", "1.0.0", 0}, // padding equality
		{"1.0", "1.1", -1},
		{"2.0", "1.9", 1},
		{"1.0-alpha", "1.0", -1}, // alpha < release
		{"1.0-alpha", "1.0-beta", -1},
		{"1.0-beta", "1.0-milestone", -1},
		{"1.0-milestone", "1.0-rc", -1},
		{"1.0-rc", "1.0-snapshot", -1},
		{"1.0-snapshot", "1.0", -1}, // snapshot < release
		{"1.0", "1.0-sp", -1},       // release < sp
		{"1.0-sp", "1.0-foo", -1},   // sp < unknown qualifier
		{"1.0", "1.0-foo", -1},      // unknown qualifier OUTRANKS release (the tricky one)
		{"1.0-rc", "1.0-rc1", -1},   // rc < rc1
		{"1.0-rc1", "1.0-rc2", -1},
		{"1.0-alpha-1", "1.0-alpha-2", -1},
		{"1.0-ga", "1.0", 0}, // ga == release
		{"1.0-final", "1.0", 0},
		// Guava-style build qualifiers (unknown → lexical, both outrank release; numeric core dominates).
		{"32.1.3-android", "32.1.3-jre", -1},
		{"32.1.3-jre", "32.1.3", 1},
		{"32.0.0", "32.1.3-jre", -1}, // numeric core dominates the qualifier
		{"1.0.1", "1.0", 1},
	}
	for _, c := range cases {
		if got := sign(compareMaven(c.a, c.b)); got != c.want {
			t.Errorf("compareMaven(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
		if got := sign(compareMaven(c.b, c.a)); got != -c.want {
			t.Errorf("compareMaven(%q,%q)=%d want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

func TestValidGatesFailClosed(t *testing.T) {
	// Garbage / unparseable versions must be rejected so a range is SKIPPED, never mis-ordered.
	for _, v := range []string{"", "  ", "not a version", "1.0 beta", "@", "1/2"} {
		if validMaven(v) {
			t.Errorf("validMaven(%q) = true, want false", v)
		}
		if validNuGet(v) {
			t.Errorf("validNuGet(%q) = true, want false", v)
		}
	}
	// Maven requires a numeric lead; a qualifier-only string is skipped.
	if validMaven("alpha") {
		t.Error("validMaven(\"alpha\") = true, want false (no numeric lead)")
	}
	// NuGet rejects a >4-segment or non-numeric core.
	if validNuGet("1.2.3.4.5") {
		t.Error("validNuGet 5-segment core should be false")
	}
	if validNuGet("1.x.0") {
		t.Error("validNuGet non-numeric core should be false")
	}
}

// TestComparatorsTransitive locks the ordering invariant the range walk + sort depend on: over a
// fixed corpus per scheme, no triple violates transitivity (a<=b<=c ⇒ a<=c, and the dual). Belt-and
// -suspenders against a future edit silently breaking the total order (golden-rule-5 critical).
func TestComparatorsTransitive(t *testing.T) {
	corpora := map[string][]string{
		"maven":    {"1", "1.0", "1.0-alpha", "1.0-beta", "1.0-milestone", "1.0-rc", "1.0-rc1", "1.0-snapshot", "1.0-sp", "1.0-foo", "1.0.1", "1.1", "2.0", "32.1.3-jre", "32.1.3-android"},
		"rubygems": {"1.0", "1.0.0", "1.0.0.a", "1.0.0.alpha", "1.0.0.beta", "1.0.0.beta.1", "1.0.1", "1.1.0", "2.0.0"},
		"nuget":    {"1.0.0", "1.0.0-alpha", "1.0.0-beta", "1.0.0-rc.1", "1.0.0.1", "1.0.1", "2.0.0"},
	}
	cmps := map[string]func(a, b string) int{"maven": compareMaven, "rubygems": compareRubyGems, "nuget": compareNuGet}
	for name, vs := range corpora {
		cmp := cmps[name]
		for _, a := range vs {
			for _, b := range vs {
				for _, c := range vs {
					ab, bc, ac := sign(cmp(a, b)), sign(cmp(b, c)), sign(cmp(a, c))
					if ab <= 0 && bc <= 0 && ac > 0 {
						t.Errorf("%s intransitive: %q<=%q<=%q but %q>%q", name, a, b, c, a, c)
					}
					if ab >= 0 && bc >= 0 && ac < 0 {
						t.Errorf("%s intransitive: %q>=%q>=%q but %q<%q", name, a, b, c, a, c)
					}
				}
			}
		}
	}
}

// TestEcosystemRangeAffected exercises the full Affected() path: an OSV ECOSYSTEM range for each
// newly-supported ecosystem now matches (previously skipped → silently no-match).
func TestEcosystemRangeAffected(t *testing.T) {
	// introduced 2.0, fixed 2.12.7 (a real-shaped Jackson/Maven range)
	mavenRanges := []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "2.0"}, {Fixed: "2.12.7"}}}}
	if !Affected("Maven", "2.5.0", mavenRanges, nil) {
		t.Error("Maven 2.5.0 must be affected by [2.0, 2.12.7)")
	}
	if Affected("Maven", "2.13.0", mavenRanges, nil) {
		t.Error("Maven 2.13.0 must NOT be affected by [2.0, 2.12.7)")
	}
	if !Affected("Maven", "32.1.3-jre", []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "30.0"}, {Fixed: "33.0"}}}}, nil) {
		t.Error("Maven 32.1.3-jre must be affected by [30.0, 33.0) (qualifier ignored for core)")
	}

	gemRanges := []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {Fixed: "5.2.4.3"}}}}
	if !Affected("RubyGems", "5.2.0", gemRanges, nil) {
		t.Error("RubyGems 5.2.0 must be affected by [0, 5.2.4.3)")
	}
	if Affected("RubyGems", "5.2.4.3", gemRanges, nil) {
		t.Error("RubyGems 5.2.4.3 (the fix) must NOT be affected")
	}

	nugetRanges := []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "4.0.0"}, {Fixed: "4.3.1"}}}}
	if !Affected("NuGet", "4.2.0", nugetRanges, nil) {
		t.Error("NuGet 4.2.0 must be affected by [4.0.0, 4.3.1)")
	}
	if Affected("NuGet", "4.3.1", nugetRanges, nil) {
		t.Error("NuGet 4.3.1 (the fix) must NOT be affected")
	}
}

// TestCompareMavenNesting covers the Apache ComparableVersion '-' sub-list nesting a flat token comparison
// gets wrong. Vectors are Apache ComparableVersion identities.
func TestCompareMavenNesting(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1-1", "1.1", -1},         // "-" after a digit nests: [1,[1]] < [1,1]
		{"1-1", "1-2", -1},         // within the nested list, numeric order holds
		{"1-0.1", "1.0.1", -1},     // a nested list sorts before an integer at the same position
		{"1-0.1", "1", 1},          // MNG-6964: the whole nested list is compared to the padded null, not just its head
		{"1.0.0-1", "1.0.0.1", -1}, // trailing zeros trimmed, then the nested "-1" sorts before ".1"
		{"1-0", "1", 0},            // "-0" nests an empty/zero list that normalizes away: 1-0 == 1
		{"1a1", "1-alpha-1", 0},    // the a/b/m shorthand + digit<->letter nesting: 1a1 == 1-alpha-1
	}
	for _, c := range cases {
		if got := sign(compareMaven(c.a, c.b)); got != c.want {
			t.Errorf("compareMaven(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
		if got := sign(compareMaven(c.b, c.a)); got != -c.want {
			t.Errorf("compareMaven(%q,%q)=%d want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}
