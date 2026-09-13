package advisory

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func confirmedSymbol(sym string) CuratedSymbol {
	return CuratedSymbol{
		Symbol: sym, Status: CuratedConfirmed, Confidence: 90,
		Provenance: CuratedProvenance{Source: "sme", Curator: "alice", ConfirmedAt: time.Unix(1, 0)},
	}
}

func TestCuratedSymbolValidate(t *testing.T) {
	if err := confirmedSymbol("pkg.Vuln").Validate(); err != nil {
		t.Fatalf("a complete confirmed symbol must validate: %v", err)
	}
	// Missing pieces are each rejected.
	cases := map[string]CuratedSymbol{
		"no symbol":            {Status: CuratedConfirmed, Confidence: 90, Provenance: CuratedProvenance{Source: "sme", Curator: "a"}},
		"bad status":           {Symbol: "x", Status: "maybe", Confidence: 90, Provenance: CuratedProvenance{Source: "sme", Curator: "a"}},
		"confidence range":     {Symbol: "x", Status: CuratedConfirmed, Confidence: 101, Provenance: CuratedProvenance{Source: "sme", Curator: "a"}},
		"no source":            {Symbol: "x", Status: CuratedConfirmed, Confidence: 90, Provenance: CuratedProvenance{Curator: "a"}},
		"confirmed no curator": {Symbol: "x", Status: CuratedConfirmed, Confidence: 90, Provenance: CuratedProvenance{Source: "sme"}},
	}
	for name, cs := range cases {
		if err := cs.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: want ErrValidation, got %v", name, err)
		}
	}
	// A CANDIDATE needs no curator (it is not yet confirmed).
	if err := (CuratedSymbol{Symbol: "x", Status: CuratedCandidate, Confidence: 40, Provenance: CuratedProvenance{Source: "ghsa-fix-commit"}}).Validate(); err != nil {
		t.Errorf("a candidate needs no curator: %v", err)
	}
	// A mangled symbol (or overload/alias) is rejected by the DOMAIN guard, so a CuratedSymbols set directly
	// on a stored advisory (bypassing the curated ingest) still cannot seed a mangled string.
	mangled := confirmedSymbol("_RNvNtCs1234_4core3fmt")
	if err := mangled.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("a mangled symbol must be rejected by Validate, got %v", err)
	}
	if syms := mangled.seedSymbols(); len(syms) != 0 {
		t.Errorf("a mangled symbol must never seed, got %v", syms)
	}
	badOverload := confirmedSymbol("pkg.Vuln")
	badOverload.Overloads = []string{"_Z3foov"}
	if err := badOverload.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("a mangled overload must be rejected, got %v", err)
	}
	// Whitespace-only provenance is rejected (a direct-domain entry must still name a source/curator).
	if err := (CuratedSymbol{Symbol: "x", Status: CuratedConfirmed, Confidence: 90, Provenance: CuratedProvenance{Source: "  ", Curator: "a"}}).Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("whitespace-only source must be rejected")
	}
	// Domain-enforced bounds: oversized symbol and too-many aux are rejected even on the direct-domain path.
	oversized := confirmedSymbol(strings.Repeat("a", MaxCuratedSymbolLen+1))
	if err := oversized.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("oversized symbol must be rejected")
	}
	tooMany := confirmedSymbol("pkg.Vuln")
	for i := 0; i <= MaxCuratedAuxSymbols; i++ {
		tooMany.Overloads = append(tooMany.Overloads, "pkg.Over")
	}
	if err := tooMany.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("too many overloads must be rejected")
	}
}

// TestSeedSymbolsTrims: a confirmed entry seeds the TRIMMED symbol, never the whitespace-padded raw value,
// so a direct-domain entry cannot inject a padded string into the match set.
func TestSeedSymbolsTrims(t *testing.T) {
	cs := confirmedSymbol("  org.example.Foo#bar  ")
	got := cs.seedSymbols()
	if len(got) != 1 || got[0] != "org.example.Foo#bar" {
		t.Fatalf("seedSymbols must emit the trimmed symbol, got %q", got)
	}
}

// TestMatchDetailsSeedsConfirmedCuratedSymbolsVersionScoped is the #1047 acceptance: a CONFIRMED curated
// symbol seeds a match ONLY on a version the block covers, a CANDIDATE never seeds, and the symbol set
// includes the confirmed entry's overloads and aliases.
func TestMatchDetailsSeedsConfirmedCuratedSymbolsVersionScoped(t *testing.T) {
	confirmed := confirmedSymbol("org.example.Foo#bar")
	confirmed.Overloads = []string{"org.example.Foo#bar$overload"}
	confirmed.Aliases = []string{"org.example.Foo#renamedBar"}
	candidate := CuratedSymbol{Symbol: "org.example.Wrapper#call", Status: CuratedCandidate, Confidence: 50, Provenance: CuratedProvenance{Source: "ghsa-fix-commit"}}
	adv := Advisory{
		ID: "GHSA-x", Affected: []AffectedPackage{{
			Ecosystem:      "Maven",
			Package:        "org.example:lib",
			Ranges:         []Range{{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "1.5.0"}}}},
			CuratedSymbols: []CuratedSymbol{confirmed, candidate},
		}},
	}

	// A version inside the affected range: the confirmed symbol + its overload/alias seed; the candidate does not.
	matched, _, syms := adv.MatchDetails("Maven", "org.example:lib", "1.0.0")
	if !matched {
		t.Fatal("1.0.0 must match the affected range")
	}
	got := map[string]bool{}
	for _, s := range syms {
		got[s] = true
	}
	for _, want := range []string{"org.example.Foo#bar", "org.example.Foo#bar$overload", "org.example.Foo#renamedBar"} {
		if !got[want] {
			t.Errorf("confirmed curated symbol %q must seed, got %v", want, syms)
		}
	}
	if got["org.example.Wrapper#call"] {
		t.Errorf("a CANDIDATE curated symbol must never seed, got %v", syms)
	}

	// A version at/after the fix: the block does not match, so NO curated symbol seeds (version-scoped).
	if matched, _, syms := adv.MatchDetails("Maven", "org.example:lib", "1.5.0"); matched || len(syms) != 0 {
		t.Errorf("a fixed version must not match or seed a curated symbol, got matched=%v syms=%v", matched, syms)
	}
}
