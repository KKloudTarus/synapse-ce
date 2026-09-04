package assessmentrelationship

import (
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestSignalValidateEnforcesStrongEvidence(t *testing.T) {
	digest := strings.Repeat("a", 64)
	valid := []Signal{
		{Kind: SignalExactBoundary, EvidenceHash: digest, SchemaVersion: SchemaVersion},
		{Kind: SignalImportedReference, EvidenceHash: digest, MatchCount: 1, ScoreMilli: 1000, SchemaVersion: SchemaVersion},
		{Kind: SignalTrustedManifest, EvidenceHash: digest, MatchCount: 1, ScoreMilli: 1000, SchemaVersion: SchemaVersion},
		{Kind: SignalDeterministicOverlap, EvidenceHash: digest, MatchCount: 2, ScoreMilli: 800, SchemaVersion: SchemaVersion},
	}
	for _, signal := range valid {
		if err := signal.Validate(); err != nil {
			t.Fatalf("valid %s signal: %v", signal.Kind, err)
		}
	}

	invalid := []Signal{
		{Kind: SignalExactBoundary, EvidenceHash: digest, MatchCount: 1, SchemaVersion: SchemaVersion},
		{Kind: SignalImportedReference, EvidenceHash: digest, MatchCount: 1, ScoreMilli: 999, SchemaVersion: SchemaVersion},
		{Kind: SignalTrustedManifest, EvidenceHash: digest, ScoreMilli: 1000, SchemaVersion: SchemaVersion},
		{Kind: SignalDeterministicOverlap, EvidenceHash: digest, MatchCount: 1, ScoreMilli: 1000, SchemaVersion: SchemaVersion},
		{Kind: SignalDeterministicOverlap, EvidenceHash: digest, MatchCount: 2, ScoreMilli: 799, SchemaVersion: SchemaVersion},
	}
	for _, signal := range invalid {
		if err := signal.Validate(); err == nil {
			t.Fatalf("invalid %s signal was accepted: %+v", signal.Kind, signal)
		}
	}
}

func TestCandidateAndRepairPlanValidateRepositoryParity(t *testing.T) {
	now := time.Date(2026, 9, 2, 1, 0, 0, 0, time.UTC)
	candidate, err := NewCandidate(Candidate{
		TenantID: "tenant", ID: "candidate", PredecessorCycleID: "cycle-a", PredecessorAssessmentID: "assessment-a",
		PredecessorRelationshipVersion: 1, PredecessorSnapshotID: "snapshot-a", PredecessorSnapshotHash: strings.Repeat("a", 64),
		SuccessorCycleID: "cycle-b", SuccessorAssessmentID: "assessment-b", SuccessorRelationshipVersion: 1,
		SuccessorSnapshotID: "snapshot-b", SuccessorSnapshotHash: strings.Repeat("b", 64), BoundaryKeyHash: strings.Repeat("c", 64),
		Signals: []Signal{
			{Kind: SignalExactBoundary, EvidenceHash: strings.Repeat("c", 64), SchemaVersion: SchemaVersion},
			{Kind: SignalImportedReference, EvidenceHash: strings.Repeat("d", 64), MatchCount: 1, ScoreMilli: 1000, SchemaVersion: SchemaVersion},
		},
		Confidence: ConfidenceMedium, ExpiresAt: now.Add(24 * time.Hour), CreatedBy: "operator", CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate.ExpiresAt = now.Add(90*time.Hour*24 + time.Second)
	if err := candidate.Validate(); err == nil {
		t.Fatal("candidate lifetime above the PostgreSQL ceiling was accepted")
	}

	body := []byte(`{"schema_version":1,"command":"assessment_cycle.merge_legacy_relationship","execution":"ready","requires":"none","candidate_id":"candidate","input_hash":"` + candidate.InputHash + `"}`)
	plan, err := NewRepairPlan(RepairPlan{TenantID: "tenant", ID: "plan", CandidateID: shared.ID("candidate"), InputHash: candidate.InputHash, Body: body, CreatedBy: "operator", CreatedAt: now})
	if err == nil {
		t.Fatalf("executable repair plan was accepted: plan=%+v", plan)
	}
}
