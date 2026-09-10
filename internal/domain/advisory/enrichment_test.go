package advisory

import "testing"

func TestPreserveEnrichmentRaisesNeverLowers(t *testing.T) {
	prior := Advisory{
		ID: "CVE-2026-0001", KEV: true, PublicExploit: true, EPSS: 0.91, EPSSPercentile: 0.99,
	}
	// A bulk-feed re-ingest of the same id: fresh base fields, no risk enrichment (all zero).
	incoming := Advisory{
		ID: "CVE-2026-0001", Summary: "refreshed summary", Severity: "HIGH",
		Affected: []AffectedPackage{{Ecosystem: "npm", Package: "left-pad"}},
	}
	got := incoming.PreserveEnrichment(prior)

	if !got.KEV || !got.PublicExploit || got.EPSS != 0.91 || got.EPSSPercentile != 0.99 {
		t.Errorf("risk signal lowered: KEV=%v PublicExploit=%v EPSS=%v pct=%v", got.KEV, got.PublicExploit, got.EPSS, got.EPSSPercentile)
	}
	// Base fields come from the incoming feed, not the prior stored advisory.
	if got.Summary != "refreshed summary" {
		t.Errorf("base Summary not refreshed: got %q", got.Summary)
	}
	if len(got.Affected) != 1 || got.Affected[0].Package != "left-pad" {
		t.Errorf("base Affected not refreshed: got %+v", got.Affected)
	}
}

func TestPreserveEnrichmentTakesHigherIncomingSignal(t *testing.T) {
	prior := Advisory{ID: "CVE-2026-0002", EPSS: 0.10, EPSSPercentile: 0.20}
	incoming := Advisory{ID: "CVE-2026-0002", KEV: true, EPSS: 0.55, EPSSPercentile: 0.80}
	got := incoming.PreserveEnrichment(prior)

	if !got.KEV {
		t.Errorf("incoming KEV lost: want true")
	}
	if got.EPSS != 0.55 || got.EPSSPercentile != 0.80 {
		t.Errorf("higher incoming signal not taken: EPSS=%v pct=%v", got.EPSS, got.EPSSPercentile)
	}
}

func TestPreserveEnrichmentDoesNotBlockNarrowing(t *testing.T) {
	// A feed that narrows an advisory (retracts an affected package, marks it withdrawn) must take effect:
	// only the monotonic risk signals carry forward, never the affected set or withdrawal.
	prior := Advisory{
		ID: "CVE-2026-0003", Withdrawn: false, KEV: true,
		Affected: []AffectedPackage{{Ecosystem: "Go", Package: "github.com/foo/bar"}, {Ecosystem: "npm", Package: "left-pad"}},
	}
	incoming := Advisory{
		ID: "CVE-2026-0003", Withdrawn: true,
		Affected: []AffectedPackage{{Ecosystem: "npm", Package: "left-pad"}},
	}
	got := incoming.PreserveEnrichment(prior)

	if !got.Withdrawn {
		t.Errorf("withdrawal not applied: a retracted advisory must take effect")
	}
	if len(got.Affected) != 1 {
		t.Errorf("affected set not narrowed: want 1 block, got %d", len(got.Affected))
	}
	if !got.KEV {
		t.Errorf("KEV enrichment lost while narrowing")
	}
}
