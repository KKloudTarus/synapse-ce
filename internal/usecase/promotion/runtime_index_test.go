package promotion

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func runtimeLoadJudgment(id, findingID, proposer string, state judgment.State, reachable judgment.ReachabilityState) judgment.Judgment {
	return judgment.Judgment{
		ID: shared.ID(id), Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: shared.ID(findingID),
		State: state, EvidenceScore: 90, ProposedBy: proposer,
		Claim: judgment.ReachabilityClaim{Reachable: reachable, Tier: judgment.TierRuntime, Confidence: 100},
	}
}

// TestIndexRuntimeLibraryLoads: a PUBLISHABLE finding-scoped reachability judgment minted by the runtime
// libloaded actor with a reachable claim produces a runtime-library signal; a proposed (unpublishable) one,
// a non-runtime actor, or a not_reachable claim does not; the lowest judgment id wins per finding.
func TestIndexRuntimeLibraryLoads(t *testing.T) {
	proposed := runtimeLoadJudgment("z-proposed", "f1", judgment.ProofActorRuntimeLibLoadedScan, judgment.StateProposed, judgment.Reachable)
	js := []judgment.Judgment{
		runtimeLoadJudgment("j2", "f1", judgment.ProofActorRuntimeLibLoadedScan, judgment.StateConfirmed, judgment.Reachable),
		runtimeLoadJudgment("j1", "f1", judgment.ProofActorRuntimeLibLoadedEngine, judgment.StateConfirmed, judgment.Reachable), // lower id wins for f1
		proposed,
		// A runtime NOT_reachable must never signal (the coordinator never mints one, but guard the index too).
		runtimeLoadJudgment("nr", "f2", judgment.ProofActorRuntimeLibLoadedScan, judgment.StateConfirmed, judgment.NotReachable),
		// A static call-graph reachable judgment is NOT a runtime-library signal (wrong actor).
		runtimeLoadJudgment("static", "f3", judgment.ProofActorCallgraphScan, judgment.StateConfirmed, judgment.Reachable),
	}
	out := indexRuntimeLibraryLoads(js)

	if sig, ok := out["f1"]; !ok || sig.ID != "j1" || sig.Kind != judgment.PromotionInputRuntimeLibrary {
		t.Fatalf("f1 must take the lowest-id publishable runtime load (j1), got %+v ok=%v", out["f1"], ok)
	}
	if _, ok := out["f2"]; ok {
		t.Fatalf("a not_reachable runtime judgment must not signal, got %+v", out["f2"])
	}
	if _, ok := out["f3"]; ok {
		t.Fatalf("a static-actor reachable judgment must not be a runtime-library signal, got %+v", out["f3"])
	}
	if len(out) != 1 {
		t.Fatalf("only f1 has a publishable runtime-library load, got %d: %+v", len(out), out)
	}
}
