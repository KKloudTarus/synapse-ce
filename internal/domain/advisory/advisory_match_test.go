package advisory

import "testing"

func TestAdvisoryMatch(t *testing.T) {
	adv := Advisory{
		ID:      "GHSA-xxxx",
		Aliases: []string{"CVE-2024-1"},
		Affected: []AffectedPackage{
			{
				Ecosystem: "Go", Package: "github.com/foo/bar",
				Ranges:       semverRange(Event{Introduced: "0"}, Event{Fixed: "1.2.0"}),
				FixedVersion: "1.2.0",
			},
		},
	}
	// affected within the range -> matched, with the block's fixed version
	if ok, fixed := adv.Match("Go", "github.com/foo/bar", "1.1.0"); !ok || fixed != "1.2.0" {
		t.Errorf("want matched with fixed 1.2.0, got ok=%v fixed=%q", ok, fixed)
	}
	// at the fixed version -> not affected
	if ok, _ := adv.Match("Go", "github.com/foo/bar", "1.2.0"); ok {
		t.Error("1.2.0 (== fixed) must not match")
	}
	// right package, WRONG ecosystem -> no match (no cross-ecosystem false hit)
	if ok, _ := adv.Match("npm", "github.com/foo/bar", "1.1.0"); ok {
		t.Error("a different ecosystem must not match")
	}
	// wrong package -> no match
	if ok, _ := adv.Match("Go", "github.com/other/pkg", "1.1.0"); ok {
		t.Error("a different package must not match")
	}
}

// TestMatchDetailsSymbolsAreVersionScoped guards the P0 soundness fix: OSV allows the same package in several
// affected[] blocks with different version ranges, each carrying its own symbols. MatchDetails must attach a
// finding ONLY the symbols of the block(s) that actually match the version, so a version-1.x finding never
// inherits a version-2.x symbol (which would seed a false "reachable vulnerable symbol"). AffectedSymbolsFor
// stays version-agnostic by contract, and this test pins the difference.
func TestMatchDetailsSymbolsAreVersionScoped(t *testing.T) {
	adv := Advisory{
		ID: "GO-multi",
		Affected: []AffectedPackage{
			{
				Ecosystem: "Go", Package: "example.com/mod",
				Ranges:          semverRange(Event{Introduced: "0"}, Event{Fixed: "1.2.0"}),
				FixedVersion:    "1.2.0",
				AffectedSymbols: []string{"example.com/mod.OldVuln"},
			},
			{
				Ecosystem: "Go", Package: "example.com/mod",
				Ranges:          semverRange(Event{Introduced: "2.0.0"}, Event{Fixed: "2.3.0"}),
				FixedVersion:    "2.3.0",
				AffectedSymbols: []string{"example.com/mod.NewVuln"},
			},
		},
	}

	// A 1.x component matches only block 1, so it must carry ONLY that block's symbol.
	matched, fixed, syms := adv.MatchDetails("Go", "example.com/mod", "1.1.0")
	if !matched || fixed != "1.2.0" {
		t.Fatalf("1.1.0: want matched fixed=1.2.0, got matched=%v fixed=%q", matched, fixed)
	}
	if len(syms) != 1 || syms[0] != "example.com/mod.OldVuln" {
		t.Errorf("1.1.0 symbols = %v; want only [example.com/mod.OldVuln] (NOT the 2.x symbol)", syms)
	}

	// A 2.x component matches only block 2.
	matched, fixed, syms = adv.MatchDetails("Go", "example.com/mod", "2.1.0")
	if !matched || fixed != "2.3.0" {
		t.Fatalf("2.1.0: want matched fixed=2.3.0, got matched=%v fixed=%q", matched, fixed)
	}
	if len(syms) != 1 || syms[0] != "example.com/mod.NewVuln" {
		t.Errorf("2.1.0 symbols = %v; want only [example.com/mod.NewVuln]", syms)
	}

	// A version in neither range does not match and yields no symbols.
	if matched, _, syms := adv.MatchDetails("Go", "example.com/mod", "1.5.0"); matched || len(syms) != 0 {
		t.Errorf("1.5.0 (gap between ranges): want no match/no symbols, got matched=%v syms=%v", matched, syms)
	}

	// AffectedSymbolsFor is version-agnostic by contract: it returns BOTH symbols. This is the exact behavior
	// MatchDetails must NOT be replaced by on the finding path.
	if all := adv.AffectedSymbolsFor("Go", "example.com/mod"); len(all) != 2 {
		t.Errorf("AffectedSymbolsFor should return both version-agnostic symbols, got %v", all)
	}
}

// TestAffectedRespectsLimit: an OSV "limit" event caps a range (exclusive upper bound), so a version at or
// beyond the limit is NOT affected even when no "fixed" closes the range.
func TestAffectedRespectsLimit(t *testing.T) {
	ranges := []Range{{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Limit: "2.0.0"}}}}
	if !Affected("Go", "1.5.0", ranges, nil) {
		t.Error("1.5.0 is below the limit 2.0.0, must be affected")
	}
	if Affected("Go", "2.0.0", ranges, nil) {
		t.Error("2.0.0 (== limit) must NOT be affected (limit is exclusive)")
	}
	if Affected("Go", "2.1.0", ranges, nil) {
		t.Error("2.1.0 (beyond the limit) must NOT be affected")
	}
}
