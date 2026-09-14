package promotion

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func runtimeLoadJudgment(id, findingID, proposer, verifier string, state judgment.State, reachable judgment.ReachabilityState, tier judgment.ReachabilityTier) judgment.Judgment {
	return judgment.Judgment{
		ID: shared.ID(id), Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: shared.ID(findingID),
		State: state, EvidenceScore: 90, ProposedBy: proposer, VerifiedBy: verifier,
		Claim: judgment.ReachabilityClaim{Reachable: reachable, Tier: tier, Confidence: 100},
	}
}

// runtimeLoad is the well-formed runtime-libloaded judgment (exact reserved pair, TierRuntime, reachable).
func runtimeLoad(id, findingID string, state judgment.State) judgment.Judgment {
	return runtimeLoadJudgment(id, findingID, judgment.ProofActorRuntimeLibLoadedScan, judgment.ProofActorRuntimeLibLoadedEngine, state, judgment.Reachable, judgment.TierRuntime)
}

// TestIndexRuntimeLibraryLoads: a PUBLISHABLE finding-scoped reachability judgment minted by the EXACT
// reserved runtime-libloaded pair (scan proposer, engine verifier) at TierRuntime with a reachable claim
// produces a runtime-library signal; a proposed (unpublishable) one, a not_reachable claim, a static
// judgment, a reversed actor pair, a wrong verifier, or a wrong tier does not; lowest judgment id wins.
func TestIndexRuntimeLibraryLoads(t *testing.T) {
	proposed := runtimeLoad("z-proposed", "f1", judgment.StateProposed)
	js := []judgment.Judgment{
		runtimeLoad("j2", "f1", judgment.StateConfirmed),
		runtimeLoad("j1", "f1", judgment.StateConfirmed), // lower id wins for f1
		proposed,
		// A runtime NOT_reachable must never signal (the coordinator never mints one, but guard the index too).
		runtimeLoadJudgment("nr", "f2", judgment.ProofActorRuntimeLibLoadedScan, judgment.ProofActorRuntimeLibLoadedEngine, judgment.StateConfirmed, judgment.NotReachable, judgment.TierRuntime),
		// A static call-graph reachable judgment is NOT a runtime-library signal (wrong actor).
		runtimeLoadJudgment("static", "f3", judgment.ProofActorCallgraphScan, judgment.ProofActorCallgraphEngine, judgment.StateConfirmed, judgment.Reachable, judgment.Tier2),
		// Reversed pair (engine proposed, scan verified): not the reserved minting pair, must not signal.
		runtimeLoadJudgment("rev", "f4", judgment.ProofActorRuntimeLibLoadedEngine, judgment.ProofActorRuntimeLibLoadedScan, judgment.StateConfirmed, judgment.Reachable, judgment.TierRuntime),
		// Right proposer, unrelated verifier: must not signal.
		runtimeLoadJudgment("badv", "f5", judgment.ProofActorRuntimeLibLoadedScan, judgment.ProofActorCallgraphEngine, judgment.StateConfirmed, judgment.Reachable, judgment.TierRuntime),
		// Right pair but wrong tier: must not signal.
		runtimeLoadJudgment("wt", "f6", judgment.ProofActorRuntimeLibLoadedScan, judgment.ProofActorRuntimeLibLoadedEngine, judgment.StateConfirmed, judgment.Reachable, judgment.Tier2),
	}
	out := indexRuntimeLibraryLoads(js)

	if sig, ok := out["f1"]; !ok || sig.ID != "j1" || sig.Kind != judgment.PromotionInputRuntimeLibrary {
		t.Fatalf("f1 must take the lowest-id publishable runtime load (j1), got %+v ok=%v", out["f1"], ok)
	}
	for _, bad := range []shared.ID{"f2", "f3", "f4", "f5", "f6"} {
		if _, ok := out[bad]; ok {
			t.Fatalf("%s must not be a runtime-library signal, got %+v", bad, out[bad])
		}
	}
	if len(out) != 1 {
		t.Fatalf("only f1 has a publishable runtime-library load, got %d: %+v", len(out), out)
	}
}
