package curatedsinks

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
)

func TestFromAdvisories(t *testing.T) {
	confirmed := advisory.CuratedSymbol{
		Symbol: "github.com/vuln/lib.Parse", Overloads: []string{"github.com/vuln/lib.ParseStrict"},
		Status: advisory.CuratedConfirmed, Confidence: 95,
		Provenance: advisory.CuratedProvenance{Source: "sme", Curator: "alice", Reference: "https://x", ConfirmedAt: time.Unix(1, 0)},
	}
	candidate := advisory.CuratedSymbol{
		Symbol: "github.com/vuln/lib.Wrapper", Status: advisory.CuratedCandidate, Confidence: 40,
		Provenance: advisory.CuratedProvenance{Source: "ghsa-fix-commit"},
	}
	advs := []advisory.Advisory{{
		ID: "GHSA-x", CWEs: []string{"CWE-502"},
		Affected: []advisory.AffectedPackage{{
			Ecosystem: "Go", Package: "github.com/vuln/lib",
			CuratedSymbols: []advisory.CuratedSymbol{confirmed, candidate},
		}},
	}}

	sinks := FromAdvisories(advs)
	// The confirmed symbol + its overload become sinks; the candidate does not.
	got := map[string]bool{}
	for _, s := range sinks {
		got[s.Symbol] = true
		if s.CWE != "CWE-502" || s.Rule != "reach-GHSA-x" {
			t.Errorf("sink %q class/rule = %s/%s", s.Symbol, s.CWE, s.Rule)
		}
		if s.Provenance == nil || s.Provenance.Advisory != "GHSA-x" || s.Provenance.Curator != "alice" {
			t.Errorf("sink %q missing provenance: %+v", s.Symbol, s.Provenance)
		}
	}
	if !got["github.com/vuln/lib.Parse"] || !got["github.com/vuln/lib.ParseStrict"] {
		t.Errorf("confirmed symbol + overload must become sinks, got %v", got)
	}
	if got["github.com/vuln/lib.Wrapper"] {
		t.Errorf("a candidate curated symbol must NOT become a sink")
	}
	if len(sinks) != 2 {
		t.Fatalf("want 2 curated sinks, got %d", len(sinks))
	}
}

func TestFromAdvisoriesEmpty(t *testing.T) {
	if s := FromAdvisories(nil); len(s) != 0 {
		t.Fatalf("no advisories -> no sinks, got %d", len(s))
	}
	// An advisory with no curated symbols contributes nothing.
	advs := []advisory.Advisory{{ID: "GHSA-y", Affected: []advisory.AffectedPackage{{Ecosystem: "Go", Package: "p"}}}}
	if s := FromAdvisories(advs); len(s) != 0 {
		t.Fatalf("no curated symbols -> no sinks, got %d", len(s))
	}
}
