package advisory

import "testing"

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.2.0", "1.10.0", -1}, // numeric, not lexical (2 < 10)
		{"1.0.1", "1.0.0", 1},
		{"1", "1.0.0", 0},                   // missing minor/patch = 0
		{"1.2", "1.2.0", 0},                 //
		{"v1.2.3", "1.2.3", 0},              // tolerate a leading v
		{"1.0.0+build1", "1.0.0+build2", 0}, // build metadata ignored
		// pre-release precedence (SemVer §11)
		{"1.0.0-alpha", "1.0.0", -1}, // a pre-release is lower than the release
		{"1.0.0", "1.0.0-rc.1", 1},
		{"1.0.0-alpha", "1.0.0-beta", -1},       // alphanumeric lexical
		{"1.0.0-alpha.1", "1.0.0-alpha.2", -1},  // numeric identifier
		{"1.0.0-alpha.2", "1.0.0-alpha.10", -1}, // numeric, not lexical
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},    // fewer identifiers < more
		{"1.0.0-1", "1.0.0-alpha", -1},          // numeric < alphanumeric
		{"1.0.0-alpha.beta", "1.0.0-beta", -1},  // discriminating §11 case (alphanumeric, fewer-id-first)
		// arbitrary-precision numeric identifiers (would overflow int64) – #2
		{"99999999999999999999999.0.0", "100000000000000000000000.0.0", -1},
		{"1.0.0-99999999999999999999999", "1.0.0-100000000000000000000000", -1},
	}
	for _, c := range cases {
		if got := CompareSemver(c.a, c.b); got != c.want {
			t.Errorf("CompareSemver(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
		// antisymmetry: compare(b,a) == -compare(a,b)
		if got := CompareSemver(c.b, c.a); got != -c.want {
			t.Errorf("CompareSemver(%q,%q) = %d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

// TestSemverCanonicalChain pins the full SemVer §11 strictly-increasing precedence chain.
func TestSemverCanonicalChain(t *testing.T) {
	chain := []string{
		"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
		"1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0",
	}
	for i := 0; i+1 < len(chain); i++ {
		if got := CompareSemver(chain[i], chain[i+1]); got != -1 {
			t.Errorf("CompareSemver(%q,%q) = %d, want -1 (§11 chain)", chain[i], chain[i+1], got)
		}
	}
}

func semverRange(events ...Event) []Range { return []Range{{Type: "SEMVER", Events: events}} }

func TestAffectedSemver(t *testing.T) {
	// introduced 0, fixed 1.2.0 -> [0, 1.2.0)
	openFixed := semverRange(Event{Introduced: "0"}, Event{Fixed: "1.2.0"})
	// introduced 1.0.0, last_affected 1.5.0 -> [1.0.0, 1.5.0]
	lastAff := semverRange(Event{Introduced: "1.0.0"}, Event{LastAffected: "1.5.0"})
	// re-introduced: affected in [1.0.0,1.2.0) and [1.5.0,1.8.0), CLEAN in [1.2.0,1.5.0)
	gapped := semverRange(
		Event{Introduced: "1.0.0"}, Event{Fixed: "1.2.0"},
		Event{Introduced: "1.5.0"}, Event{Fixed: "1.8.0"},
	)
	// #1 BLOCKER regression: fixed then re-introduced AT THE SAME version (1.2.0) re-opens [1.2.0,∞).
	reopen := semverRange(Event{Introduced: "0"}, Event{Fixed: "1.2.0"}, Event{Introduced: "1.2.0"})
	// zero-width [introduced 1.2.0, fixed 1.2.0] excludes 1.2.0 (affects nothing).
	zeroWidth := semverRange(Event{Introduced: "1.2.0"}, Event{Fixed: "1.2.0"})
	// events supplied OUT OF VERSION ORDER must sort to the same result as openFixed.
	outOfOrder := semverRange(Event{Fixed: "1.2.0"}, Event{Introduced: "0"})

	cases := []struct {
		name, version string
		ranges        []Range
		want          bool
	}{
		{"in [0,fixed)", "1.1.0", openFixed, true},
		{"at fixed (exclusive)", "1.2.0", openFixed, false},
		{"above fixed", "2.0.0", openFixed, false},
		{"early version in [0,..)", "0.0.1", openFixed, true},
		{"below introduced", "0.9.0", lastAff, false},
		{"at last_affected (inclusive)", "1.5.0", lastAff, true},
		{"above last_affected", "1.5.1", lastAff, false},
		{"within first interval", "1.1.0", gapped, true},
		{"in the FIXED gap", "1.3.0", gapped, false},
		{"within second interval", "1.6.0", gapped, true},
		{"at second fixed", "1.8.0", gapped, false},
		{"prerelease below fixed is affected", "1.2.0-rc1", openFixed, true}, // 1.2.0-rc1 < 1.2.0
		{"empty version never affected", "", openFixed, false},
		// #1 reopen-at-same-version: 1.2.0+ is affected again (the dangerous false-negative case)
		{"reopen at fixed version", "1.2.0", reopen, true},
		{"reopen above fixed version", "1.3.0", reopen, true},
		{"reopen still affected early", "1.1.0", reopen, true},
		// zero-width excludes the point and affects nothing
		{"zero-width excludes the point", "1.2.0", zeroWidth, false},
		{"zero-width below", "1.1.0", zeroWidth, false},
		{"zero-width above", "1.3.0", zeroWidth, false},
		// out-of-order events still match correctly (sort is load-bearing)
		{"out-of-order in interval", "1.1.0", outOfOrder, true},
		{"out-of-order at fixed", "1.2.0", outOfOrder, false},
		// #3/#4 fail-closed: garbage / over-long versions never match
		{"garbage version fail-closed", "abc", openFixed, false},
		{"over-long version fail-closed", "1.2.3.4", openFixed, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := AffectedSemver(c.version, c.ranges); got != c.want {
				t.Errorf("AffectedSemver(%q) = %v, want %v", c.version, got, c.want)
			}
		})
	}
}

func TestAffectedVersionList(t *testing.T) {
	list := []string{"1.0.0", "1.2.3", "2.0.0-rc1"}
	cases := []struct {
		version string
		want    bool
	}{
		{"1.2.3", true},
		{"v1.2.3", true},    // leading v normalized on the query side
		{"2.0.0-rc1", true}, // prerelease exact
		{"1.1.0", false},    // not enumerated
		{"1.2.3.0", false},  // not an exact token
		{"", false},         // empty fail-closed
	}
	for _, c := range cases {
		if got := AffectedVersionList(c.version, list); got != c.want {
			t.Errorf("AffectedVersionList(%q) = %v, want %v", c.version, got, c.want)
		}
	}
	// leading v on the LISTED side is also normalized
	if !AffectedVersionList("1.5.0", []string{"v1.5.0"}) {
		t.Error("a listed 'v1.5.0' must match a '1.5.0' query")
	}
}

func TestAffectedEntryPointORs(t *testing.T) {
	// Affected = explicit-versions OR semver-range (OSV alternatives).
	ranges := semverRange(Event{Introduced: "0"}, Event{Fixed: "1.2.0"})
	versions := []string{"3.0.0"} // out of the range, but explicitly listed
	if !Affected("Go", "1.1.0", ranges, nil) {
		t.Error("in-range version must be Affected via the range")
	}
	if !Affected("Go", "3.0.0", ranges, versions) {
		t.Error("explicitly-listed version must be Affected even when outside every range")
	}
	if Affected("Go", "2.5.0", ranges, versions) {
		t.Error("a version neither in-range nor listed must NOT be Affected")
	}
}

func TestAffectedSemverSkipsNonSemver(t *testing.T) {
	// a non-SEMVER range (ECOSYSTEM/GIT) is not matched by this matcher (handled elsewhere) – so a
	// version is NOT reported affected via it here.
	ranges := []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {Fixed: "1.2.0"}}}}
	if AffectedSemver("1.1.0", ranges) {
		t.Error("a non-SEMVER range must be skipped by AffectedSemver")
	}
	if AffectedSemver("1.1.0", nil) {
		t.Error("no ranges -> not affected")
	}
}
