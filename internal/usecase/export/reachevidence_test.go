package export

import (
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func reachJ(findingID string, st judgment.State, claim judgment.ReachabilityClaim) judgment.Judgment {
	return judgment.Judgment{
		Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: shared.ID(findingID),
		State: st, EvidenceScore: 90, Claim: claim,
	}
}

func TestDeriveReachabilityEvidence(t *testing.T) {
	// No judgments at all: explicit no_analysis (never silently absent).
	if ev := DeriveReachabilityEvidence(nil, "f1"); ev == nil || ev.Label != LabelNoAnalysis || ev.Source != "reachability" {
		t.Fatalf("no judgments must derive no_analysis, got %+v", ev)
	}

	// A publishable reachable claim -> reachable, carrying the call path.
	reach := []judgment.Judgment{reachJ("f1", judgment.StateConfirmed, judgment.ReachabilityClaim{
		Reachable: judgment.Reachable, Tier: judgment.Tier2, Confidence: 90, Path: []string{"app.main", "vuln.Sink"}})}
	ev := DeriveReachabilityEvidence(reach, "f1")
	if ev.Label != LabelReachable || ev.Tier != judgment.Tier2 || !reflect.DeepEqual(ev.Path, []string{"app.main", "vuln.Sink"}) {
		t.Fatalf("reachable claim must derive reachable + path, got %+v", ev)
	}

	// A proven not_reachable (Tier-1 import, complete coverage) -> present_unreached.
	proven := []judgment.Judgment{reachJ("f1", judgment.StateConfirmed, judgment.ReachabilityClaim{
		Reachable: judgment.NotReachable, Tier: judgment.Tier1, Confidence: 90})}
	if ev := DeriveReachabilityEvidence(proven, "f1"); ev.Label != LabelPresentUnreached {
		t.Fatalf("a proven not_reachable must derive present_unreached, got %+v", ev)
	}

	// An UNPROVEN not_reachable (Tier-2, no entry points) is NOT a sound present_unreached: no_analysis.
	unproven := []judgment.Judgment{reachJ("f1", judgment.StateConfirmed, judgment.ReachabilityClaim{
		Reachable: judgment.NotReachable, Tier: judgment.Tier2, Confidence: 90})}
	if ev := DeriveReachabilityEvidence(unproven, "f1"); ev.Label != LabelNoAnalysis {
		t.Fatalf("an unproven not_reachable must not overstate present_unreached, got %+v", ev)
	}

	// A reachable claim is never shadowed by a same-finding proven not_reachable at a lower tier.
	mixed := []judgment.Judgment{
		reachJ("f1", judgment.StateConfirmed, judgment.ReachabilityClaim{Reachable: judgment.NotReachable, Tier: judgment.Tier1, Confidence: 90}),
		reachJ("f1", judgment.StateConfirmed, judgment.ReachabilityClaim{Reachable: judgment.Reachable, Tier: judgment.Tier2, Confidence: 90, Path: []string{"a.b"}}),
	}
	if ev := DeriveReachabilityEvidence(mixed, "f1"); ev.Label != LabelReachable {
		t.Fatalf("a reachable claim must win over a lower-tier not_reachable, got %+v", ev)
	}

	// A judgment for a DIFFERENT finding does not leak into this finding's evidence.
	if ev := DeriveReachabilityEvidence(reach, "other"); ev.Label != LabelNoAnalysis {
		t.Fatalf("another finding's judgment must not leak, got %+v", ev)
	}

	// A conditionally_reachable claim derives the conditionally_reachable label (never no_analysis, never
	// present_unreached), carrying the call path.
	cond := []judgment.Judgment{reachJ("f1", judgment.StateConfirmed, judgment.ReachabilityClaim{
		Reachable: judgment.ConditionallyReachable, Tier: judgment.Tier2, Confidence: 90, Path: []string{"a.b"}})}
	if ev := DeriveReachabilityEvidence(cond, "f1"); ev.Label != LabelConditionallyReachable || len(ev.Path) != 1 {
		t.Fatalf("conditionally_reachable claim must derive the conditionally_reachable label + path, got %+v", ev)
	}
}
