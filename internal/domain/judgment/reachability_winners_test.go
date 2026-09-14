package judgment

import "testing"

// TestWinningReachabilityClaimsAndReachableIDs pins the shared reconciliation snapshot both the VEX export
// and VEX apply paths read: only publishable finding-scoped reachability claims count, a superseding claim
// wins, and ReachableFindingIDs is exactly the reachable winners.
func TestWinningReachabilityClaimsAndReachableIDs(t *testing.T) {
	js := []Judgment{
		// f1: a weaker Tier-1 not_reachable then a stronger Tier-2 reachable -> reachable wins.
		{Capability: CapReachability, SubjectKind: SubjectFinding, SubjectID: "f1", State: StateConfirmed, EvidenceScore: 90, Claim: ReachabilityClaim{Reachable: NotReachable, Tier: Tier1, Confidence: 90}},
		{Capability: CapReachability, SubjectKind: SubjectFinding, SubjectID: "f1", State: StateConfirmed, EvidenceScore: 90, Claim: ReachabilityClaim{Reachable: Reachable, Tier: Tier2, Confidence: 90, EntrypointsPresent: true}},
		// f2: reachable but only PROPOSED -> not publishable -> excluded entirely.
		{Capability: CapReachability, SubjectKind: SubjectFinding, SubjectID: "f2", State: StateProposed, Claim: ReachabilityClaim{Reachable: Reachable, Tier: Tier2, Confidence: 90}},
		// f3: a non-reachability capability about a finding -> ignored.
		{Capability: CapSAST, SubjectKind: SubjectFinding, SubjectID: "f3", State: StateConfirmed, EvidenceScore: 90, Claim: ReachabilityClaim{Reachable: Reachable, Tier: Tier2}},
		// f4: reachable, publishable.
		{Capability: CapReachability, SubjectKind: SubjectFinding, SubjectID: "f4", State: StateConfirmed, EvidenceScore: 90, Claim: ReachabilityClaim{Reachable: Reachable, Tier: Tier1, Confidence: 90}},
	}
	winner := WinningReachabilityClaims(js)
	if got := winner["f1"].Reachable; got != Reachable {
		t.Errorf("f1 winner must be reachable (Tier-2 supersedes Tier-1 not_reachable), got %q", got)
	}
	if _, ok := winner["f2"]; ok {
		t.Error("a proposed (non-publishable) judgment must be excluded from the winner set")
	}
	if _, ok := winner["f3"]; ok {
		t.Error("a non-reachability capability must be excluded")
	}
	reach := ReachableFindingIDs(winner)
	if !reach["f1"] || !reach["f4"] {
		t.Errorf("f1 and f4 must be reachable, got %v", reach)
	}
	if reach["f2"] || reach["f3"] {
		t.Errorf("f2/f3 must not be reachable, got %v", reach)
	}
}

// TestSuppressionResistantIncludesConditional pins that a conditionally_reachable finding is
// suppression-resistant (a vendor not_affected must not suppress it) even though it is not strictly
// Reachable, while a not_reachable finding is not resistant. Reachable is a subset of resistant.
func TestSuppressionResistantIncludesConditional(t *testing.T) {
	js := []Judgment{
		{Capability: CapReachability, SubjectKind: SubjectFinding, SubjectID: "reach", State: StateConfirmed, EvidenceScore: 90, Claim: ReachabilityClaim{Reachable: Reachable, Tier: Tier2, Confidence: 90, EntrypointsPresent: true}},
		{Capability: CapReachability, SubjectKind: SubjectFinding, SubjectID: "cond", State: StateConfirmed, EvidenceScore: 90, Claim: ReachabilityClaim{Reachable: ConditionallyReachable, Tier: Tier2, Confidence: 90, EntrypointsPresent: true}},
		{Capability: CapReachability, SubjectKind: SubjectFinding, SubjectID: "not", State: StateConfirmed, EvidenceScore: 90, Claim: ReachabilityClaim{Reachable: NotReachable, Tier: Tier2, Confidence: 90, EntrypointsPresent: true}},
	}
	winner := WinningReachabilityClaims(js)
	resistant := SuppressionResistantFindingIDs(winner)
	if !resistant["reach"] || !resistant["cond"] {
		t.Errorf("both reachable and conditionally_reachable must be suppression-resistant, got %v", resistant)
	}
	if resistant["not"] {
		t.Errorf("a not_reachable finding must not be suppression-resistant, got %v", resistant)
	}
	// Reachable is strictly a subset: the reachable-only set excludes the conditional one.
	if reach := ReachableFindingIDs(winner); reach["cond"] {
		t.Errorf("ReachableFindingIDs must be strictly reachable (exclude conditional), got %v", reach)
	}
}
