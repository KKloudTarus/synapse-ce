package judgment

import "testing"

func TestReachabilityStateRank(t *testing.T) {
	if !(Reachable.Rank() > NotReachable.Rank() && NotReachable.Rank() > ReachUnknown.Rank()) {
		t.Fatalf("state rank must order reachable > not_reachable > unknown, got %d,%d,%d",
			Reachable.Rank(), NotReachable.Rank(), ReachUnknown.Rank())
	}
}

func TestSupersedesStateAwareWithinTier(t *testing.T) {
	reachable := ReachabilityClaim{Reachable: Reachable, Tier: Tier2}
	notReach := ReachabilityClaim{Reachable: NotReachable, Tier: Tier2}
	// A proven reachable supersedes a same-tier not_reachable (upgrade).
	if !reachable.Supersedes(notReach) {
		t.Error("same-tier reachable must supersede not_reachable")
	}
	// A weaker not_reachable must NOT shadow a proven same-tier reachable (the false-negative the fix closes).
	if notReach.Supersedes(reachable) {
		t.Error("same-tier not_reachable must NOT supersede reachable")
	}
	// Equal state + tier: no supersession (no churn).
	if reachable.Supersedes(reachable) {
		t.Error("equal state and tier must not supersede")
	}
	// A higher-tier PROVEN not_reachable still supersedes a lower-tier reachable (legitimate refinement).
	provenNotReach := ReachabilityClaim{Reachable: NotReachable, Tier: Tier2, EntrypointsPresent: true}
	if !provenNotReach.Supersedes(ReachabilityClaim{Reachable: Reachable, Tier: Tier1}) {
		t.Error("a higher-tier proven not_reachable must supersede a lower-tier reachable")
	}
	// A higher-tier UNPROVEN not_reachable must NOT shadow a lower-tier reachable: an unproven negative
	// is noise, not a stronger proof, so it can never blunt a reachable signal (EPIC #1042, 0.6).
	if notReach.Supersedes(ReachabilityClaim{Reachable: Reachable, Tier: Tier1}) {
		t.Error("a higher-tier unproven not_reachable must NOT supersede a lower-tier reachable")
	}
}

func TestProvedNotReachable(t *testing.T) {
	if !(ReachabilityClaim{Reachable: NotReachable, Tier: Tier2}).ProvedNotReachable() {
		t.Error("a complete not_reachable is a proof")
	}
	if (ReachabilityClaim{Reachable: NotReachable, UnknownSymbols: []string{"x"}}).ProvedNotReachable() {
		t.Error("an unanswered affected symbol is not a proof")
	}
	if (ReachabilityClaim{Reachable: NotReachable, BlindConstructs: []string{"reflection"}}).ProvedNotReachable() {
		t.Error("a blind construct on the reachable surface is not a proof")
	}
	if (ReachabilityClaim{Reachable: Reachable}).ProvedNotReachable() {
		t.Error("a reachable claim is not a not-reachable proof")
	}
}

func TestSuppressesFinding(t *testing.T) {
	// A complete Tier-1 (import) not_reachable suppresses: import reachability has no entry-point notion.
	if !(ReachabilityClaim{Reachable: NotReachable, Tier: Tier1}).SuppressesFinding() {
		t.Error("a complete Tier-1 not_reachable must suppress")
	}
	// A Tier-2 (call-graph) not_reachable WITHOUT entry points is soft no-coverage, not proof.
	if (ReachabilityClaim{Reachable: NotReachable, Tier: Tier2}).SuppressesFinding() {
		t.Error("a zero-entrypoint Tier-2 not_reachable must NOT suppress")
	}
	// Tier-0 (presence) and Tier-1.5 (bounded source call-path, e.g. JVM class-closure) are reflection-blind
	// and must NOT suppress, even with complete coverage recorded.
	if (ReachabilityClaim{Reachable: NotReachable, Tier: Tier1_5}).SuppressesFinding() {
		t.Error("a Tier-1.5 not_reachable is reflection-blind and must NOT suppress")
	}
	if (ReachabilityClaim{Reachable: NotReachable, Tier: Tier0}).SuppressesFinding() {
		t.Error("a Tier-0 not_reachable must NOT suppress")
	}
	// A Tier-2 not_reachable WITH entry points and full coverage suppresses.
	if !(ReachabilityClaim{Reachable: NotReachable, Tier: Tier2, EntrypointsPresent: true}).SuppressesFinding() {
		t.Error("a proven Tier-2 not_reachable (entry points, full coverage) must suppress")
	}
	// A partial or blind negative never suppresses, regardless of tier or entry points.
	if (ReachabilityClaim{Reachable: NotReachable, Tier: Tier2, EntrypointsPresent: true, UnknownSymbols: []string{"x"}}).SuppressesFinding() {
		t.Error("a partial not_reachable must NOT suppress")
	}
	if (ReachabilityClaim{Reachable: NotReachable, Tier: Tier1, BlindConstructs: []string{"reflection"}}).SuppressesFinding() {
		t.Error("a blind not_reachable must NOT suppress")
	}
	// A reachable claim never suppresses (it only raises).
	if (ReachabilityClaim{Reachable: Reachable, Tier: Tier2, EntrypointsPresent: true}).SuppressesFinding() {
		t.Error("a reachable claim must not be a suppression basis")
	}
}
