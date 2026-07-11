package advisory

import "testing"

// TestAffectedEcosystemPyPI: a PyPI ECOSYSTEM range is matched with PEP 440 ordering – including the cases
// SemVer gets wrong (a post-release is still inside [0, 2.0); a dev-release of the fixed version is below it).
func TestAffectedEcosystemPyPI(t *testing.T) {
	r := []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {Fixed: "2.0"}}}}
	cases := []struct {
		v    string
		want bool
	}{
		{"1.0", true},
		{"1.9.9", true},
		{"1.0.post1", true},  // post-release still < 2.0
		{"2.0.dev1", true},   // dev-release of 2.0 is BELOW 2.0 → still in range
		{"2.0", false},       // == fixed (exclusive)
		{"2.0.post1", false}, // post-release of the fixed version is ABOVE it → not affected
		{"2.1", false},
	}
	for _, c := range cases {
		if got := Affected("PyPI", c.v, r, nil); got != c.want {
			t.Errorf("Affected(PyPI, %q) = %v, want %v", c.v, got, c.want)
		}
	}
}

// TestAffectedEcosystemSemverEcosystems: ECOSYSTEM ranges for the SemVer-versioned ecosystems are matched by
// SemVer (these were previously skipped).
func TestAffectedEcosystemSemverEcosystems(t *testing.T) {
	r := []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {Fixed: "1.2.0"}}}}
	for _, eco := range []string{"Go", "npm", "crates.io"} {
		if !Affected(eco, "1.1.0", r, nil) {
			t.Errorf("%s ECOSYSTEM range must match 1.1.0", eco)
		}
		if Affected(eco, "1.2.0", r, nil) {
			t.Errorf("%s 1.2.0 (== fixed) must not match", eco)
		}
	}
}

// TestAffectedGitRangeSkipped: a GIT range is never order-matched (no commit graph) – only the explicit
// versions list signals affectedness.
func TestAffectedGitRangeSkipped(t *testing.T) {
	r := []Range{{Type: "GIT", Events: []Event{{Introduced: "0"}, {Fixed: "deadbeef"}}}}
	if Affected("Go", "1.0.0", r, nil) {
		t.Error("a GIT range must be skipped (no commit-graph ordering)")
	}
	if !Affected("Go", "1.0.0", r, []string{"1.0.0"}) {
		t.Error("a GIT-only advisory still matches via the explicit versions list")
	}
}

// TestAffectedUnsupportedEcosystemFailsClosed: an ecosystem with NO owned comparator yet (Hex, Pub,
// Packagist, Swift, …) still skips ECOSYSTEM ranges – versions list only, never a guessed-order false
// match. (Maven/RubyGems/NuGet are now SUPPORTED via versions_eco.go – see versions_eco_test.go.)
func TestAffectedUnsupportedEcosystemFailsClosed(t *testing.T) {
	r := []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {Fixed: "2.0"}}}}
	for _, eco := range []string{"Hex", "Pub", "Packagist", "SwiftURL"} {
		if Affected(eco, "1.0", r, nil) {
			t.Errorf("%s ECOSYSTEM range must fail closed (no comparator)", eco)
		}
		if !Affected(eco, "1.0", r, []string{"1.0"}) {
			t.Errorf("%s still matches via the explicit versions list", eco)
		}
	}
}

// TestAffectedPyPIUnparseableFailsClosed: a PyPI component version that isn't valid PEP 440 never matches a
// range (fail-closed – no false hit on garbage).
func TestAffectedPyPIUnparseableFailsClosed(t *testing.T) {
	r := []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {Fixed: "2.0"}}}}
	if Affected("PyPI", "not-a-version", r, nil) {
		t.Error("an unparseable PyPI version must fail closed")
	}
}

// TestAdvisoryMatchPyPIEcosystem is the end-to-end Match path with a PyPI advisory (PEP 440 ECOSYSTEM range).
func TestAdvisoryMatchPyPIEcosystem(t *testing.T) {
	adv := Advisory{
		ID: "GHSA-pypi-1",
		Affected: []AffectedPackage{{
			Ecosystem: "PyPI", Package: "django",
			Ranges:       []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {Fixed: "4.2.0"}}}},
			FixedVersion: "4.2.0",
		}},
	}
	if ok, fixed := adv.Match("PyPI", "django", "4.1.post1"); !ok || fixed != "4.2.0" {
		t.Errorf("PyPI 4.1.post1 in [0, 4.2.0) must match with fixed 4.2.0: ok=%v fixed=%q", ok, fixed)
	}
	if ok, _ := adv.Match("PyPI", "django", "4.2.0"); ok {
		t.Error("4.2.0 (== fixed) must not match")
	}
}
