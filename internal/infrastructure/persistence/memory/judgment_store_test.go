package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func memoryTestArtifact(t *testing.T, id string) judgment.ArtifactIdentity {
	t.Helper()
	sum := sha256.Sum256([]byte(id))
	artifact, err := judgment.NewArtifactIdentity(id, "sha256:"+hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func memoryTestSuppressionProof(t *testing.T) judgment.ReachabilitySuppressionProof {
	t.Helper()
	registry, err := judgment.NewInitialReachabilityAuthorityRegistry()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := registry.Lookup(string(judgment.CohortGo), string(judgment.ModeSourceTier2))
	if err != nil {
		t.Fatal(err)
	}
	approval, ok := policy.Approval()
	if !ok {
		t.Fatal("expected go reachability suppression approval")
	}
	snapshot, err := judgment.NewReachabilitySnapshotIdentity(memoryTestArtifact(t, "source"), memoryTestArtifact(t, "sbom"), memoryTestArtifact(t, "run"))
	if err != nil {
		t.Fatal(err)
	}
	contract := approval.Contract()
	contractIdentity, err := judgment.NewArtifactIdentity(contract.ID(), contract.Digest())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := judgment.NewReachabilitySuppressionProof(judgment.ReachabilitySuppressionProofInput{
		SubjectID: "f1", BoundaryID: "analysis-boundary", Cohort: string(judgment.CohortGo), Mode: string(judgment.ModeSourceTier2), Snapshot: snapshot,
		Analyzer: memoryTestArtifact(t, "analyzer"), Configuration: memoryTestArtifact(t, "configuration"), CompletenessContract: contractIdentity,
		Authority: approval.Authority(), AuthorityCheckpoint: memoryTestArtifact(t, "authority-checkpoint"), Proposer: approval.Proposer(), Verifier: approval.Verifier(),
	})
	if err != nil {
		t.Fatal(err)
	}
	proof, err = proof.WithProposalEvidence(memoryTestArtifact(t, "proposal-evidence"))
	if err != nil {
		t.Fatal(err)
	}
	proof, err = proof.WithVerdictEvidence(memoryTestArtifact(t, "verdict-evidence"))
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestJudgmentStoreSuppressionProofRoundTrip(t *testing.T) {
	store := NewJudgmentStore()
	proof := memoryTestSuppressionProof(t)
	item := judgment.Judgment{
		ID: "j-proof", EngagementID: "e1", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "f1",
		Claim: judgment.ReachabilityClaim{Reachable: judgment.NotReachable, Tier: judgment.Tier2, EntrypointsPresent: true}, State: judgment.StateConfirmed, EvidenceScore: 90,
		ProposedBy: proof.Proposer(), VerifiedBy: proof.Verifier(), Version: 2, SuppressionProof: &proof,
	}
	if err := store.Save(context.Background(), item); err != nil {
		t.Fatalf("save suppression proof: %v", err)
	}
	stored, err := store.ListByEngagement(context.Background(), "e1")
	if err != nil || len(stored) != 1 || stored[0].SuppressionProof == nil {
		t.Fatalf("suppression proof round trip = %#v err=%v", stored, err)
	}
	if !stored[0].SuppressionProof.ProposalEvidence().Equal(proof.ProposalEvidence()) || !stored[0].SuppressionProof.VerdictEvidence().Equal(proof.VerdictEvidence()) {
		t.Fatalf("sealed evidence changed during memory round trip: %#v", stored[0].SuppressionProof)
	}

	transition := judgment.Judgment{
		ID: "j-transition", EngagementID: "e1", Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "f1",
		Claim: judgment.ReachabilityClaim{Reachable: judgment.NotReachable, Tier: judgment.Tier2, EntrypointsPresent: true}, State: judgment.StateProposed,
		ProposedBy: proof.Proposer(), Version: 1,
	}
	if err := store.Save(context.Background(), transition); err != nil {
		t.Fatal(err)
	}
	transitioned, err := store.SetVerdictStateWithAudit(context.Background(), "e1", transition.ID, 90, judgment.StateConfirmed, proof.Verifier(), "confirmed", &proof, 1, ports.AuditEntry{Actor: proof.Verifier(), Action: "judgment.verdict", Target: transition.ID.String()})
	if err != nil || transitioned.SuppressionProof == nil || !transitioned.SuppressionProof.VerdictEvidence().Equal(proof.VerdictEvidence()) {
		t.Fatalf("verdict transition did not persist suppression proof: %#v err=%v", transitioned, err)
	}

	invalid := item
	invalid.ID = "j-invalid"
	invalid.SuppressionProof = judgment.MalformedReachabilitySuppressionProof()
	if err := store.Save(context.Background(), invalid); err == nil {
		t.Fatal("malformed suppression proof was accepted by memory storage")
	}
}

func TestJudgmentStore(t *testing.T) {
	st := NewJudgmentStore()
	ctx := context.Background()
	j := judgment.Judgment{
		ID: "j1", EngagementID: "e1", Capability: judgment.CapReachability,
		SubjectKind: judgment.SubjectFinding, SubjectID: "f1", State: judgment.StateProposed, Version: 1,
	}
	if err := st.Save(ctx, j); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.ListByEngagement(ctx, "e1"); len(got) != 1 || got[0].ID != "j1" {
		t.Fatalf("ListByEngagement: %+v", got)
	}
	if got, _ := st.ListBySubject(ctx, "e1", "f1"); len(got) != 1 {
		t.Fatalf("ListBySubject: %+v", got)
	}
	if got, _ := st.ListBySubject(ctx, "e1", "other"); len(got) != 0 {
		t.Fatalf("ListBySubject other: %+v", got)
	}

	upd, err := st.SetScoreState(ctx, "e1", "j1", 80, judgment.StateConfirmed, 1)
	if err != nil {
		t.Fatal(err)
	}
	if upd.EvidenceScore != 80 || upd.State != judgment.StateConfirmed || upd.Version != 2 || upd.VerifiedBy != "" || upd.VerdictRationale != "" {
		t.Fatalf("SetScoreState: %+v", upd)
	}
	provenance, err := st.SetVerdictState(ctx, "e1", "j1", 91, judgment.StateConfirmed, "human:verifier", "reproduced", 2)
	if err != nil {
		t.Fatal(err)
	}
	if provenance.VerifiedBy != "human:verifier" || provenance.VerdictRationale != "reproduced" || provenance.EvidenceScore != 91 || provenance.Version != 3 {
		t.Fatalf("SetVerdictState lost provenance: %#v", provenance)
	}
	accepted, err := st.SetScoreState(ctx, "e1", "j1", 91, judgment.StateConfirmed, 3)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.VerifiedBy != "human:verifier" || accepted.VerdictRationale != "reproduced" || accepted.Version != 4 {
		t.Fatalf("SetScoreState cleared sealed provenance: %#v", accepted)
	}
	// stale expectedVersion → conflict (lost-update guard)
	if _, err := st.SetScoreState(ctx, "e1", "j1", 90, judgment.StateRefuted, 3); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale version: want ErrConflict, got %v", err)
	}
	// unknown id → not found
	if _, err := st.SetScoreState(ctx, "e1", "nope", 1, judgment.StateConfirmed, 4); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown id: want ErrNotFound, got %v", err)
	}

	// Save is insert-only: a re-Save of an existing id must NOT clobber score/state (mirror
	// postgres ON CONFLICT DO NOTHING). The row is currently confirmed/80/v2 from SetScoreState.
	clobber := j
	clobber.State = judgment.StateProposed
	clobber.EvidenceScore = 0
	clobber.Version = 99
	if err := st.Save(ctx, clobber); err != nil {
		t.Fatal(err)
	}
	again, _ := st.ListByEngagement(ctx, "e1")
	if again[0].EvidenceScore != 91 || again[0].State != judgment.StateConfirmed || again[0].Version != 4 || again[0].VerifiedBy != "human:verifier" || again[0].VerdictRationale != "reproduced" {
		t.Fatalf("re-Save clobbered an existing row: %+v", again[0])
	}
}
