package finding

import "testing"

// TestRequiresEvidenceGate pins the R4 predicate: gate on PROVENANCE (ProposedBy), plus
// KindExploitation as a defensive belt, normalizing an empty Kind to SCA – and never letting a
// missing signal remove the gate.
func TestRequiresEvidenceGate(t *testing.T) {
	cases := []struct {
		name       string
		proposedBy string
		kind       Kind
		want       bool
	}{
		{"AI-proposed sast gated", "agent:s1", KindSAST, true},
		{"human sast ungated", "", KindSAST, false},
		{"exploitation gated by belt", "", KindExploitation, true},
		{"AI-proposed empty-kind gated (provenance)", "agent:s1", "", true},
		{"empty-kind, no proposer = sca, ungated", "", "", false},
		{"manual ungated", "", KindManual, false},
		{"sca ungated", "", KindSCA, false},
		{"AI-proposed threat gated", "agent:s1", KindThreat, true},
		{"human dast ungated", "", KindDAST, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &Finding{ProposedBy: tc.proposedBy, Kind: tc.kind}
			if got := f.RequiresEvidenceGate(); got != tc.want {
				t.Fatalf("RequiresEvidenceGate(proposedBy=%q,kind=%q)=%v want %v", tc.proposedBy, tc.kind, got, tc.want)
			}
		})
	}
}

// TestPublishableExcludesUnprovenAIClaim: an AI-proposed sast finding below the bar must be
// filtered from deliverables (the generalized gate now covers sast, not just exploitation).
func TestPublishableExcludesUnprovenAIClaim(t *testing.T) {
	f := Finding{Kind: KindSAST, ProposedBy: "agent:s1", EvidenceScore: 10}
	if f.CanPromote() {
		t.Fatal("AI sast below bar must not promote")
	}
	if out := Publishable([]Finding{f}); len(out) != 0 {
		t.Fatalf("AI sast below bar must be filtered, got %d", len(out))
	}
	f.EvidenceScore = EvidenceThreshold
	if !f.CanPromote() {
		t.Fatal("AI sast at bar should promote")
	}
}
