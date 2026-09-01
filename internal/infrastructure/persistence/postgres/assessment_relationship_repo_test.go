package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentrelationship"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestPostgresAssessmentRelationshipRepositoryLifecycleConcurrencyAndRLS(t *testing.T) {
	db, dsn := newMigration0140DB(t)
	if err := goose.UpTo(db, ".", 150); err != nil {
		t.Fatalf("up to 0150: %v", err)
	}
	ctx := context.Background()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	suffix := fmt.Sprintf("relationship-%d", time.Now().UnixNano())
	tenantID, candidate := seedPostgresRelationshipSubjects(t, ctx, pool, suffix)
	repository := NewAssessmentRelationshipRepository(pool)

	stored, created, err := repository.CreateCandidate(ctx, candidate)
	if err != nil || !created || stored.Candidate.ID != candidate.ID {
		t.Fatalf("create candidate=%+v created=%v err=%v", stored, created, err)
	}
	replayCandidate := candidate
	replayCandidate.ID = shared.ID("relationship-replay-" + suffix)
	replayedCandidate, created, err := repository.CreateCandidate(ctx, replayCandidate)
	if err != nil || created || replayedCandidate.Candidate.ID != candidate.ID {
		t.Fatalf("replay candidate=%+v created=%v err=%v", replayedCandidate, created, err)
	}
	if _, err := repository.GetCandidate(ctx, shared.ID("other-"+suffix), candidate.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant candidate error=%v", err)
	}

	now := candidate.CreatedAt.Add(time.Minute)
	plan := postgresRelationshipPlan(t, candidate, shared.ID("relationship-plan-"+suffix), "reviewer", now)
	decision := postgresRelationshipDecision(candidate, shared.ID("relationship-decision-"+suffix), assessmentrelationship.DecisionConfirm, "reviewer", "confirm-key", "Confirmed deterministic relationship", plan.ID, now)
	confirmed, replayed, err := repository.DecideCandidateCAS(ctx, decision, &plan)
	if err != nil || replayed || confirmed.Decision == nil || confirmed.Plan == nil || confirmed.Decision.Action != assessmentrelationship.DecisionConfirm {
		t.Fatalf("confirm=%+v replayed=%v err=%v", confirmed, replayed, err)
	}
	replayedRecord, replayed, err := repository.DecideCandidateCAS(ctx, decision, &plan)
	if err != nil || !replayed || replayedRecord.Decision == nil || replayedRecord.Decision.ID != decision.ID {
		t.Fatalf("decision replay=%+v replayed=%v err=%v", replayedRecord, replayed, err)
	}
	mismatch := decision
	mismatch.RequestHash = postgresRelationshipDigest("different request")
	if _, _, err := repository.DecideCandidateCAS(ctx, mismatch, &plan); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("idempotency mismatch error=%v", err)
	}

	for table, statement := range map[string]string{
		"candidate": `UPDATE assessment_relationship_candidates SET created_by=created_by WHERE tenant_id=$1 AND id=$2`,
		"decision":  `UPDATE assessment_relationship_decisions SET actor=actor WHERE tenant_id=$1 AND candidate_id=$2`,
		"plan":      `UPDATE assessment_relationship_repair_plans SET created_by=created_by WHERE tenant_id=$1 AND candidate_id=$2`,
	} {
		if err := WithTenant(ctx, pool, tenantID.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, statement, tenantID.String(), candidate.ID.String())
			return err
		}); err == nil {
			t.Fatalf("append-only %s accepted mutation", table)
		}
	}
	if err := WithTenant(ctx, pool, tenantID.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `TRUNCATE assessment_relationship_decisions`)
		return err
	}); err == nil {
		t.Fatal("append-only decision table accepted truncate")
	}

	concurrent := candidate
	concurrent.ID = shared.ID("relationship-concurrent-" + suffix)
	concurrent.Signals = []assessmentrelationship.Signal{
		{Kind: assessmentrelationship.SignalExactBoundary, EvidenceHash: candidate.BoundaryKeyHash, SchemaVersion: assessmentrelationship.SchemaVersion},
		{Kind: assessmentrelationship.SignalImportedReference, EvidenceHash: strings.Repeat("d", 64), MatchCount: 1, ScoreMilli: 1000, SchemaVersion: assessmentrelationship.SchemaVersion},
	}
	concurrent, err = assessmentrelationship.NewCandidate(concurrent)
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := repository.CreateCandidate(ctx, concurrent); err != nil || !created {
		t.Fatalf("concurrent candidate created=%v err=%v", created, err)
	}
	decisions := []assessmentrelationship.Decision{
		postgresRelationshipDecision(concurrent, shared.ID("relationship-race-reject-"+suffix), assessmentrelationship.DecisionReject, "reviewer-a", "race-reject", "Rejected concurrent evidence", "", now.Add(time.Second)),
		postgresRelationshipDecision(concurrent, shared.ID("relationship-race-dismiss-"+suffix), assessmentrelationship.DecisionDismiss, "reviewer-b", "race-dismiss", "Dismissed concurrent evidence", "", now.Add(time.Second)),
	}
	start := make(chan struct{})
	errorsByIndex := make([]error, len(decisions))
	var wait sync.WaitGroup
	for index := range decisions {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			_, _, errorsByIndex[index] = repository.DecideCandidateCAS(ctx, decisions[index], nil)
		}(index)
	}
	close(start)
	wait.Wait()
	winners, conflicts := 0, 0
	for _, err := range errorsByIndex {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, shared.ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent error=%v", err)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatalf("concurrent winners=%d conflicts=%d errors=%v", winners, conflicts, errorsByIndex)
	}

	mismatched := candidate
	mismatched.ID = shared.ID("relationship-mismatched-owner-" + suffix)
	mismatched.SuccessorSnapshotID = candidate.PredecessorSnapshotID
	mismatched.SuccessorSnapshotHash = candidate.PredecessorSnapshotHash
	mismatched.Signals = []assessmentrelationship.Signal{
		{Kind: assessmentrelationship.SignalExactBoundary, EvidenceHash: candidate.BoundaryKeyHash, SchemaVersion: assessmentrelationship.SchemaVersion},
		{Kind: assessmentrelationship.SignalImportedReference, EvidenceHash: strings.Repeat("e", 64), MatchCount: 1, ScoreMilli: 1000, SchemaVersion: assessmentrelationship.SchemaVersion},
	}
	mismatched, err = assessmentrelationship.NewCandidate(mismatched)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repository.CreateCandidate(ctx, mismatched); err == nil {
		t.Fatal("composite snapshot ownership FK accepted a cross-cycle snapshot")
	}

	for _, table := range []string{"assessment_relationship_candidates", "assessment_relationship_repair_plans", "assessment_relationship_decisions"} {
		var forced bool
		if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&forced); err != nil || !forced {
			t.Fatalf("FORCE RLS %s=%v err=%v", table, forced, err)
		}
	}
}

func seedPostgresRelationshipSubjects(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) (shared.ID, assessmentrelationship.Candidate) {
	t.Helper()
	tenantID := shared.ID("tenant-" + suffix)
	cycleRepository := NewAssessmentCycleRepository(pool)
	snapshotRepository := NewAssessmentSnapshotRepository(pool)
	runRepository := NewScanRunStore(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	type subject struct {
		cycleID, assessmentID, snapshotID, runID shared.ID
		snapshotHash                             string
	}
	subjects := []subject{
		{cycleID: shared.ID("relationship-cycle-a-" + suffix), assessmentID: shared.ID("relationship-assessment-a-" + suffix), snapshotID: shared.ID("relationship-snapshot-a-" + suffix), runID: shared.ID("relationship-run-a-" + suffix)},
		{cycleID: shared.ID("relationship-cycle-b-" + suffix), assessmentID: shared.ID("relationship-assessment-b-" + suffix), snapshotID: shared.ID("relationship-snapshot-b-" + suffix), runID: shared.ID("relationship-run-b-" + suffix)},
	}
	for index := range subjects {
		item := &subjects[index]
		ensureTestTenantAndEngagement(t, ctx, pool, tenantID, item.assessmentID, "", "")
		cycle, err := assessmentcycle.NewAssessmentCycle(item.cycleID, tenantID, item.cycleID.String(), assessmentcycle.BoundaryStandalone, "", "", item.assessmentID, "operator", now)
		if err != nil {
			t.Fatal(err)
		}
		member, err := assessmentcycle.NewInitialMember(tenantID, item.cycleID, item.assessmentID, "operator", now)
		if err != nil {
			t.Fatal(err)
		}
		if err := cycleRepository.CreateCycle(ctx, cycle); err != nil {
			t.Fatal(err)
		}
		if err := cycleRepository.CreateMember(ctx, member); err != nil {
			t.Fatal(err)
		}
		resultHash := strings.Repeat(string(rune('a'+index)), 64)
		run := postgresNativeRun(t, tenantID, item.assessmentID, item.runID, resultHash)
		if err := runRepository.Begin(ctx, beginningPostgresScanRun(run)); err != nil {
			t.Fatal(err)
		}
		if err := run.Seal(scanrun.StatusSucceeded, 1, now); err != nil {
			t.Fatal(err)
		}
		if err := runRepository.Seal(ctx, run); err != nil {
			t.Fatal(err)
		}
		snapshot := postgresAssessmentSnapshot(t, tenantID, item.cycleID, item.assessmentID, item.snapshotID.String(), "request-"+item.snapshotID.String(), run)
		stored, created, err := snapshotRepository.CreateFinalizedCAS(ctx, snapshot, 0)
		if err != nil || !created {
			t.Fatalf("create relationship snapshot=%+v created=%v err=%v", stored, created, err)
		}
		item.snapshotHash = stored.ContentHash
	}
	boundaryHash := postgresRelationshipDigest("standalone-boundary")
	candidate, err := assessmentrelationship.NewCandidate(assessmentrelationship.Candidate{
		TenantID: tenantID, ID: shared.ID("relationship-candidate-" + suffix),
		PredecessorCycleID: subjects[0].cycleID, PredecessorAssessmentID: subjects[0].assessmentID, PredecessorRelationshipVersion: 1,
		PredecessorSnapshotID: subjects[0].snapshotID, PredecessorSnapshotHash: subjects[0].snapshotHash,
		SuccessorCycleID: subjects[1].cycleID, SuccessorAssessmentID: subjects[1].assessmentID, SuccessorRelationshipVersion: 1,
		SuccessorSnapshotID: subjects[1].snapshotID, SuccessorSnapshotHash: subjects[1].snapshotHash, BoundaryKeyHash: boundaryHash,
		Signals: []assessmentrelationship.Signal{
			{Kind: assessmentrelationship.SignalExactBoundary, EvidenceHash: boundaryHash, SchemaVersion: assessmentrelationship.SchemaVersion},
			{Kind: assessmentrelationship.SignalImportedReference, EvidenceHash: strings.Repeat("c", 64), MatchCount: 1, ScoreMilli: 1000, SchemaVersion: assessmentrelationship.SchemaVersion},
		},
		Confidence: assessmentrelationship.ConfidenceMedium, ExpiresAt: now.Add(30 * 24 * time.Hour), CreatedBy: "operator", CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tenantID, candidate
}

func postgresRelationshipDecision(candidate assessmentrelationship.Candidate, id shared.ID, action assessmentrelationship.DecisionAction, actor, key, reason string, planID shared.ID, now time.Time) assessmentrelationship.Decision {
	return assessmentrelationship.Decision{
		TenantID: candidate.TenantID, ID: id, CandidateID: candidate.ID, Action: action, Actor: actor, Reason: reason,
		IdempotencyKey: key, RequestHash: postgresRelationshipDigest(string(action) + "\x00" + reason), ExpectedVersion: 1,
		Version: 2, RepairPlanID: planID, CreatedAt: now,
	}
}

func postgresRelationshipPlan(t *testing.T, candidate assessmentrelationship.Candidate, id shared.ID, actor string, now time.Time) assessmentrelationship.RepairPlan {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"schema_version": assessmentrelationship.SchemaVersion, "command": "assessment_cycle.merge_legacy_relationship",
		"execution": "blocked", "requires": "separately_approved_move_merge_command", "candidate_id": candidate.ID, "input_hash": candidate.InputHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := assessmentrelationship.NewRepairPlan(assessmentrelationship.RepairPlan{TenantID: candidate.TenantID, ID: id, CandidateID: candidate.ID, InputHash: candidate.InputHash, Body: body, CreatedBy: actor, CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func postgresRelationshipDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
