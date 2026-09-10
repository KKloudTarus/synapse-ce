package advisory

import "testing"

// A labeled version-range matching corpus across ecosystems (EPIC #860 D8.4). Each vector is
// (ecosystem, installed version, advisory range/explicit versions) -> affected?, exercising the
// per-ecosystem comparators that decide Affected/AffectedVersionList: npm/Go/crates.io SemVer, PEP 440
// (epochs, pre-releases, trailing zeros), Maven ComparableVersion, and the dpkg/apk/rpm distro orderings
// (epochs, tildes, backport suffixes). The corpus is the accuracy contract these comparators are held to;
// a comparator regression flips a vector. Fail-closed cases (unknown ecosystem, GIT range, unparseable
// version) must never match.

// ecoRange builds an ECOSYSTEM-type range with an optional introduced and fixed bound.
func ecoRange(introduced, fixed string) Range {
	var ev []Event
	if introduced != "" {
		ev = append(ev, Event{Introduced: introduced})
	}
	if fixed != "" {
		ev = append(ev, Event{Fixed: fixed})
	}
	return Range{Type: "ECOSYSTEM", Events: ev}
}

func TestVersionRangeCorpus(t *testing.T) {
	cases := []struct {
		name     string
		eco      string
		version  string
		ranges   []Range
		versions []string
		want     bool
	}{
		// ---- SemVer ecosystems (npm / Go / crates.io) ----
		{"npm in range", "npm", "4.17.20", []Range{ecoRange("4.0.0", "4.17.21")}, nil, true},
		{"npm at fixed is not affected", "npm", "4.17.21", []Range{ecoRange("4.0.0", "4.17.21")}, nil, false},
		{"npm below introduced", "npm", "3.9.9", []Range{ecoRange("4.0.0", "4.17.21")}, nil, false},
		{"npm prerelease sorts below release bound", "npm", "1.0.0-rc.1", []Range{ecoRange("1.0.0", "")}, nil, false},
		{"go v-prefix normalized", "Go", "v1.5.0", []Range{ecoRange("1.0.0", "2.0.0")}, nil, true},
		{"crates zero-introduced is from the beginning", "crates.io", "0.2.0", []Range{ecoRange("0", "0.3.0")}, nil, true},

		// ---- PyPI (PEP 440) ----
		{"pypi trailing-zero equality via versions list", "PyPI", "1.0.0", nil, []string{"1.0"}, true},
		{"pypi prerelease below release bound", "PyPI", "1.0rc1", []Range{ecoRange("1.0", "")}, nil, false},
		{"pypi in range", "PyPI", "2.0", []Range{ecoRange("1.0", "3.0")}, nil, true},
		{"pypi epoch outranks an epoch-0 range", "PyPI", "1!2.0", []Range{ecoRange("2.0", "3.0")}, nil, false},
		{"pypi unparseable version fails closed", "PyPI", "not-a-version", []Range{ecoRange("1.0", "2.0")}, nil, false},

		// ---- Maven (ComparableVersion) ----
		{"maven qualifier equality via versions list", "Maven", "1.0.0", nil, []string{"1.0"}, true},
		{"maven alpha qualifier sorts below release", "Maven", "1.0-alpha", []Range{ecoRange("1.0", "2.0")}, nil, false},
		{"maven in range", "Maven", "1.5", []Range{ecoRange("1.0", "2.0")}, nil, true},

		// ---- Debian / Ubuntu (dpkg) ----
		{"debian revision in range", "Debian", "1.0-1", []Range{ecoRange("0", "1.0-2")}, nil, true},
		{"debian at fixed revision is not affected", "Debian", "1.0-2", []Range{ecoRange("0", "1.0-2")}, nil, false},
		{"debian tilde sorts below the release", "Debian", "1.0~rc1-1", []Range{ecoRange("1.0-1", "")}, nil, false},
		{"debian epoch outranks an epoch-0 range", "Debian", "2:1.0-1", []Range{ecoRange("1.0", "3.0")}, nil, false},
		{"debian backport tilde sorts below the release", "Debian", "1.0-1~bpo11+1", []Range{ecoRange("1.0-1", "")}, nil, false},

		// ---- Alpine (apk) ----
		{"alpine revision in range", "Alpine", "1.0.0-r0", []Range{ecoRange("0", "1.0.0-r1")}, nil, true},
		{"alpine at fixed revision is not affected", "Alpine", "1.0.0-r1", []Range{ecoRange("0", "1.0.0-r1")}, nil, false},
		{"alpine above fixed revision", "Alpine", "1.0.0-r2", []Range{ecoRange("0", "1.0.0-r1")}, nil, false},

		// ---- RPM distros (Red Hat / Rocky / …) ----
		{"redhat release in range", "Red Hat", "1.0-1.el9", []Range{ecoRange("0", "1.0-2.el9")}, nil, true},
		{"redhat at fixed release is not affected", "Red Hat", "1.0-2.el9", []Range{ecoRange("0", "1.0-2.el9")}, nil, false},
		{"redhat epoch outranks an epoch-0 range", "Red Hat", "1:1.0-1.el9", []Range{ecoRange("1.0", "2.0")}, nil, false},
		{"redhat tilde sorts below the release", "Red Hat", "1.0~beta-1.el9", []Range{ecoRange("1.0-1.el9", "")}, nil, false},

		// ---- Fail-closed: no owned comparator / GIT range / unknown ecosystem ----
		{"git range is skipped", "npm", "1.0.0", []Range{{Type: "GIT", Events: []Event{{Introduced: "0"}}}}, nil, false},
		{"unknown ecosystem fails closed", "totally-unknown", "1.0.0", []Range{ecoRange("0", "2.0")}, nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Affected(tc.eco, tc.version, tc.ranges, tc.versions); got != tc.want {
				t.Errorf("Affected(%q, %q, %+v, %v) = %v, want %v", tc.eco, tc.version, tc.ranges, tc.versions, got, tc.want)
			}
		})
	}
}

// TestVersionRangeCorpusFuzzyCPE exercises the fuzzy NVD/CPE comparator (CompareFuzzy/OrderableFuzzy) that
// orders the arbitrary product-version forms CPE bounds carry: 4-part versions, qualifier tails, and
// numeric-not-lexical ordering. This is the comparator cpeMatch uses for an NVD range (EPIC #860 D2.3/D8.4).
func TestVersionRangeCorpusFuzzyCPE(t *testing.T) {
	lt := func(a, b string) {
		if CompareFuzzy(a, b) >= 0 {
			t.Errorf("CompareFuzzy(%q, %q) >= 0, want a < b", a, b)
		}
	}
	eq := func(a, b string) {
		if CompareFuzzy(a, b) != 0 {
			t.Errorf("CompareFuzzy(%q, %q) != 0, want equal", a, b)
		}
	}
	lt("9.0.62", "9.0.62.1")     // a 4th numeric part orders higher
	lt("2.0", "10.0")            // numeric ordering, not lexical ("10" > "2")
	lt("1.2.3.RELEASE", "1.2.4") // the numeric core dominates the qualifier tail
	eq("9.0.62.1", "9.0.62.1")
	if !OrderableFuzzy("9.0.62.1") {
		t.Error("a 4-part version must be orderable")
	}
}
