package ownadvisory

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func mavenAdvisory() advisory.Advisory {
	return advisory.Advisory{
		ID:      "GHSA-abcd",
		Aliases: []string{"CVE-2024-9999"},
		Affected: []advisory.AffectedPackage{{
			Ecosystem: "Maven",
			Package:   "org.example:lib",
			Ranges:    []advisory.Range{{Type: "SEMVER", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.0.0"}}}},
		}},
	}
}

// TestApplyConfirmedSeedsAndCandidateDoesNot: a confirmed entry attaches and seeds via MatchDetails; a
// candidate attaches but never seeds; a wrong-ecosystem/package entry does not attach at all (inert).
func TestApplyConfirmedSeedsAndCandidateDoesNot(t *testing.T) {
	corpus := CuratedCorpus{
		normID("CVE-2024-9999"): { // keyed by an ALIAS: must still attach to the GHSA advisory
			{AdvisoryID: "CVE-2024-9999", Ecosystem: "Maven", Package: "org.example:lib", Symbol: "org.example.Foo#sink",
				Status: "confirmed", Confidence: 95, Source: "sme", Curator: "alice", ConfirmedAt: time.Unix(1, 0)},
			{AdvisoryID: "CVE-2024-9999", Ecosystem: "Maven", Package: "org.example:lib", Symbol: "org.example.Wrapper#call",
				Status: "candidate", Confidence: 40, Source: "ghsa-fix-commit"},
			{AdvisoryID: "CVE-2024-9999", Ecosystem: "PyPI", Package: "other", Symbol: "other.mod.f", // wrong ecosystem+package
				Status: "confirmed", Confidence: 95, Source: "sme", Curator: "alice"},
		},
	}
	adv := corpus.Apply(mavenAdvisory())
	// Only the two Maven entries attach; the PyPI/other entry is inert (never touches this block).
	if n := len(adv.Affected[0].CuratedSymbols); n != 2 {
		t.Fatalf("want 2 attached Maven entries, got %d: %+v", n, adv.Affected[0].CuratedSymbols)
	}
	_, _, syms := adv.MatchDetails("Maven", "org.example:lib", "1.0.0")
	seen := map[string]bool{}
	for _, s := range syms {
		seen[s] = true
	}
	if !seen["org.example.Foo#sink"] {
		t.Errorf("confirmed curated symbol must seed, got %v", syms)
	}
	if seen["org.example.Wrapper#call"] {
		t.Errorf("candidate curated symbol must never seed, got %v", syms)
	}
	if seen["other.mod.f"] {
		t.Errorf("wrong-ecosystem entry must be inert, got %v", syms)
	}
}

// TestApplySeedingIsVersionScopedByBlockRange: an entry attaches to matching (ecosystem, package) blocks,
// and seeding is scoped by each block's affected range, so a curated symbol never seeds on a version the
// advisory does not mark affected (the #1047 acceptance: never seed on a non-matching version).
func TestApplySeedingIsVersionScopedByBlockRange(t *testing.T) {
	adv := advisory.Advisory{
		ID: "GHSA-multi",
		Affected: []advisory.AffectedPackage{
			{Ecosystem: "Maven", Package: "org.example:lib", Ranges: []advisory.Range{{Type: "SEMVER", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.0.0"}}}}},
			{Ecosystem: "Maven", Package: "org.example:lib", Ranges: []advisory.Range{{Type: "SEMVER", Events: []advisory.Event{{Introduced: "2.0.0"}, {Fixed: "2.5.0"}}}}},
		},
	}
	corpus := CuratedCorpus{normID("GHSA-multi"): {
		{AdvisoryID: "GHSA-multi", Ecosystem: "Maven", Package: "org.example:lib",
			Symbol: "org.example.Foo#sink", Status: "confirmed", Confidence: 90, Source: "sme", Curator: "bob"},
	}}
	adv = corpus.Apply(adv)
	// Seeds for a version inside an affected range.
	if _, _, syms := adv.MatchDetails("Maven", "org.example:lib", "0.5.0"); len(syms) != 1 || syms[0] != "org.example.Foo#sink" {
		t.Errorf("must seed for an affected version, got %v", syms)
	}
	if _, _, syms := adv.MatchDetails("Maven", "org.example:lib", "2.1.0"); len(syms) != 1 || syms[0] != "org.example.Foo#sink" {
		t.Errorf("must seed for the second affected range, got %v", syms)
	}
	// Does NOT seed for a version between the ranges (1.5.0 is fixed in the first range, before the second).
	if matched, _, syms := adv.MatchDetails("Maven", "org.example:lib", "1.5.0"); matched || len(syms) != 0 {
		t.Errorf("must not seed for an unaffected version, got matched=%v syms=%v", matched, syms)
	}
}

// seedsVia reports whether an entry, once attached to a fresh advisory, seeds symbol via MatchDetails at an
// affected version (the public seeding path).
func seedsVia(t *testing.T, e CuratedEntry) bool {
	t.Helper()
	corpus := CuratedCorpus{normID(e.AdvisoryID): {e}}
	adv := corpus.Apply(mavenAdvisory())
	_, _, syms := adv.MatchDetails("Maven", "org.example:lib", "1.0.0")
	for _, s := range syms {
		if s == e.Symbol {
			return true
		}
	}
	return false
}

func TestConfirmWorkflow(t *testing.T) {
	candidate := CuratedEntry{AdvisoryID: "CVE-2024-9999", Ecosystem: "Maven", Package: "org.example:lib",
		Symbol: "org.example.Foo#sink", Status: "candidate", Confidence: 50, Source: "ghsa-fix-commit"}
	// A candidate attaches but does not seed.
	if seedsVia(t, candidate) {
		t.Fatal("a candidate must not seed")
	}
	// Confirm requires a curator.
	if _, err := candidate.Confirm("", time.Unix(1, 0)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("confirm without curator must fail, got %v", err)
	}
	confirmed, err := candidate.Confirm("alice", time.Unix(1, 0))
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if !seedsVia(t, confirmed) {
		t.Fatal("a confirmed entry must seed")
	}
}

func TestToCuratedSymbolRejectsMangled(t *testing.T) {
	// A mangled Rust v0 symbol must be rejected (demangle before curation), not stored as if a source symbol.
	e := CuratedEntry{AdvisoryID: "GHSA-x", Ecosystem: "crates.io", Package: "lib",
		Symbol: "_RNvNtCs1234_4core3fmt", Status: "confirmed", Confidence: 90, Source: "sme", Curator: "alice"}
	if _, err := e.toCuratedSymbol(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a mangled curated symbol must be rejected, got %v", err)
	}
}

func TestLoadCuratedCorpus(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "batch.json")
	body := `[{"advisoryId":"CVE-1","ecosystem":"Maven","package":"org.example:lib","symbol":"org.example.Foo#sink","status":"confirmed","confidence":90,"source":"sme","curator":"alice"}]`
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	corpus, err := LoadCuratedCorpus(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(corpus[normID("CVE-1")]) != 1 {
		t.Fatalf("want one loaded entry, got %+v", corpus)
	}
	// A blank dir disables the corpus.
	if c, err := LoadCuratedCorpus(""); err != nil || c != nil {
		t.Fatalf("blank dir must disable corpus: %+v %v", c, err)
	}
}
