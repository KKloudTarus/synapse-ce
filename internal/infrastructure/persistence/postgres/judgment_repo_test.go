package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func postgresTestArtifact(t *testing.T, id string) judgment.ArtifactIdentity {
	t.Helper()
	sum := sha256.Sum256([]byte(id))
	artifact, err := judgment.NewArtifactIdentity(id, "sha256:"+hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func postgresTestSuppressionProof(t *testing.T) judgment.ReachabilitySuppressionProof {
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
		t.Fatal("expected eligible go suppression approval")
	}
	snapshot, err := judgment.NewReachabilitySnapshotIdentity(postgresTestArtifact(t, "source"), postgresTestArtifact(t, "sbom"), postgresTestArtifact(t, "run"))
	if err != nil {
		t.Fatal(err)
	}
	contract := approval.Contract()
	contractIdentity, err := judgment.NewArtifactIdentity(contract.ID(), contract.Digest())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := judgment.NewReachabilitySuppressionProof(judgment.ReachabilitySuppressionProofInput{
		SubjectID: "f-proof", BoundaryID: "analysis-boundary", Cohort: string(judgment.CohortGo), Mode: string(judgment.ModeSourceTier2), Snapshot: snapshot,
		Analyzer: postgresTestArtifact(t, "analyzer"), Configuration: postgresTestArtifact(t, "configuration"), CompletenessContract: contractIdentity,
		Authority: approval.Authority(), AuthorityCheckpoint: postgresTestArtifact(t, "authority-checkpoint"), Proposer: approval.Proposer(), Verifier: approval.Verifier(),
	})
	if err != nil {
		t.Fatal(err)
	}
	proof, err = proof.WithProposalEvidence(postgresTestArtifact(t, "proposal-evidence"))
	if err != nil {
		t.Fatal(err)
	}
	proof, err = proof.WithVerdictEvidence(postgresTestArtifact(t, "verdict-evidence"))
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

// Integration test – runs only when SYNAPSE_TEST_DB_DSN points at a Postgres.
func TestJudgmentRepository(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := shared.WithTenant(context.Background(), shared.DefaultTenant)
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	eid := shared.ID("jt-" + randHex(t))
	e, err := engagement.New(eid, "", "judgment-test", "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := NewEngagementRepository(pool).Create(ctx, e); err != nil {
		t.Fatalf("create engagement: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM judgments WHERE engagement_id=$1", eid.String())
		_, _ = pool.Exec(ctx, "DELETE FROM engagements WHERE id=$1", eid.String())
	})

	repo := NewJudgmentRepository(pool)
	now := time.Now().UTC().Truncate(time.Second)
	jid := shared.ID("jid-" + randHex(t))
	j, err := judgment.New(jid, eid, judgment.CapReachability, judgment.SubjectFinding, "f1",
		judgment.ReachabilityClaim{Reachable: "not_reachable", Tier: "tier-1.5", Confidence: 90}, "agent:s1", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Save(ctx, j); err != nil {
		t.Fatalf("save: %v", err)
	}

	// round-trip: claim decodes fail-closed back to the typed value
	list, err := repo.ListByEngagement(ctx, eid)
	if err != nil || len(list) != 1 || list[0].ID != jid {
		t.Fatalf("ListByEngagement: %+v err=%v", list, err)
	}
	if list[0].State != judgment.StateProposed || list[0].EvidenceScore != 0 || list[0].VerifiedBy != "" || list[0].VerdictRationale != "" || list[0].SuppressionProof != nil {
		t.Fatalf("want legacy proposed/0/empty provenance, got %#v", list[0])
	}
	if rc, ok := list[0].Claim.(judgment.ReachabilityClaim); !ok || rc.Tier != "tier-1.5" {
		t.Fatalf("claim did not round-trip typed: %#v", list[0].Claim)
	}
	if bySub, _ := repo.ListBySubject(ctx, eid, "f1"); len(bySub) != 1 {
		t.Fatalf("ListBySubject: %+v", bySub)
	}

	// Score/state updates for acceptance must not invent or clear verdict provenance.
	upd, err := repo.SetScoreState(ctx, eid, jid, 80, judgment.StateConfirmed, 1)
	if err != nil {
		t.Fatalf("SetScoreState: %v", err)
	}
	if upd.EvidenceScore != 80 || upd.State != judgment.StateConfirmed || upd.Version != 2 || upd.VerifiedBy != "" || upd.VerdictRationale != "" {
		t.Fatalf("SetScoreState result: %+v", upd)
	}

	// A verdict transition round-trips its sealed provenance through storage.
	verdictState, err := repo.SetVerdictState(ctx, eid, jid, 90, judgment.StateConfirmed, "human:verifier", "reproduced", 2)
	if err != nil {
		t.Fatalf("SetVerdictState: %v", err)
	}
	if verdictState.EvidenceScore != 90 || verdictState.Version != 3 || verdictState.VerifiedBy != "human:verifier" || verdictState.VerdictRationale != "reproduced" {
		t.Fatalf("SetVerdictState result: %+v", verdictState)
	}
	list, err = repo.ListByEngagement(ctx, eid)
	if err != nil || len(list) != 1 || list[0].VerifiedBy != "human:verifier" || list[0].VerdictRationale != "reproduced" {
		t.Fatalf("verdict provenance did not round-trip: %+v err=%v", list, err)
	}

	// stale version → conflict (lost-update guard)
	if _, err := repo.SetScoreState(ctx, eid, jid, 90, judgment.StateRefuted, 2); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale version: want ErrConflict, got %v", err)
	}
	// unknown id → not found
	if _, err := repo.SetScoreState(ctx, eid, shared.ID("nope"), 1, judgment.StateConfirmed, 3); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown id: want ErrNotFound, got %v", err)
	}

	proof := postgresTestSuppressionProof(t)
	proofJudgment := judgment.Judgment{
		ID: shared.ID("j-proof-" + randHex(t)), EngagementID: eid, Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "f-proof",
		Claim: judgment.ReachabilityClaim{Reachable: judgment.NotReachable, Tier: judgment.Tier2, EntrypointsPresent: true}, State: judgment.StateConfirmed, EvidenceScore: 90,
		ProposedBy: proof.Proposer(), VerifiedBy: proof.Verifier(), Version: 2, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}, SuppressionProof: &proof,
	}
	if err := repo.Save(ctx, proofJudgment); err != nil {
		t.Fatalf("save suppression proof: %v", err)
	}
	storedProof, err := repo.GetByID(ctx, eid, proofJudgment.ID)
	if err != nil || storedProof.SuppressionProof == nil {
		t.Fatalf("suppression proof round trip = %#v err=%v", storedProof, err)
	}
	if !storedProof.SuppressionProof.ProposalEvidence().Equal(proof.ProposalEvidence()) || !storedProof.SuppressionProof.VerdictEvidence().Equal(proof.VerdictEvidence()) {
		t.Fatalf("sealed evidence changed during postgres round trip: %#v", storedProof.SuppressionProof)
	}

	transitionID := shared.ID("j-transition-" + randHex(t))
	if err := repo.Save(ctx, judgment.Judgment{
		ID: transitionID, EngagementID: eid, Capability: judgment.CapReachability, SubjectKind: judgment.SubjectFinding, SubjectID: "f-proof",
		Claim: judgment.ReachabilityClaim{Reachable: judgment.NotReachable, Tier: judgment.Tier2, EntrypointsPresent: true}, State: judgment.StateProposed,
		ProposedBy: proof.Proposer(), Version: 1, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}); err != nil {
		t.Fatalf("save transition judgment: %v", err)
	}
	transitioned, err := repo.SetVerdictStateWithAudit(ctx, eid, transitionID, 90, judgment.StateConfirmed, proof.Verifier(), "confirmed", &proof, 1, ports.AuditEntry{Actor: proof.Verifier(), Action: "judgment.verdict", Target: transitionID.String(), At: now})
	if err != nil || transitioned.SuppressionProof == nil || !transitioned.SuppressionProof.VerdictEvidence().Equal(proof.VerdictEvidence()) {
		t.Fatalf("verdict transition did not persist suppression proof: %#v err=%v", transitioned, err)
	}

	malformedID := "j-malformed-" + randHex(t)
	if _, err := pool.Exec(ctx,
		`INSERT INTO judgments (id, tenant_id, engagement_id, capability, subject_kind, subject_id, claim, state, evidence_score, proposed_by, verified_by, verdict_rationale, suppression_provenance, version, created_at, updated_at)
		 VALUES ($1,'default',$2,'reachability','finding','f-malformed','{"capability":"reachability","claim":{"reachable":"not_reachable","tier":"tier-2","confidence":90,"entrypoints_present":true}}','confirmed',90,'system:callgraph-scan','system:callgraph-engine','confirmed','{"unexpected":true}',1,now(),now())`,
		malformedID, eid.String()); err != nil {
		t.Fatalf("insert malformed provenance row: %v", err)
	}
	malformed, err := repo.GetByID(ctx, eid, shared.ID(malformedID))
	if err != nil || malformed.SuppressionProof == nil || len(malformed.SuppressionProof.MissingProvenance()) != 1 || malformed.SuppressionProof.MissingProvenance()[0] != judgment.ProvenanceMalformed {
		t.Fatalf("malformed provenance did not fail closed on read: %#v err=%v", malformed, err)
	}

	// fail-closed on a corrupted enum row (defense-in-depth): a hand-edited row with a junk state
	// must be rejected on read, never hydrated. (Last assertion – it poisons ListByEngagement.)
	if _, err := pool.Exec(ctx,
		`INSERT INTO judgments (id, tenant_id, engagement_id, capability, subject_kind, subject_id, claim, state, version, created_at, updated_at)
		 VALUES ($1,'default',$2,'reachability','finding','f1','{"capability":"reachability","claim":{"reachable":"unknown","tier":"tier-0","confidence":0}}','GARBAGE',1,now(),now())`,
		"jbad-"+randHex(t), eid.String()); err != nil {
		t.Fatalf("insert corrupted row: %v", err)
	}
	if _, err := repo.ListByEngagement(ctx, eid); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("corrupted enum row should fail-closed on read, got %v", err)
	}
}
