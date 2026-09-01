package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	snapshotuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestPostgresAssessmentSnapshotRepositoryRLSCASReplayAndImmutability(t *testing.T) {
	ctx, pool := setupTestDB(t)
	suffix := time.Now().UnixNano()
	tenantA := shared.ID(fmt.Sprintf("snapshot-tenant-a-%d", suffix))
	tenantB := shared.ID(fmt.Sprintf("snapshot-tenant-b-%d", suffix))
	assessmentID := shared.ID(fmt.Sprintf("snapshot-assessment-%d", suffix))
	cycleID := shared.ID(fmt.Sprintf("snapshot-cycle-%d", suffix))
	ensureTestTenantAndEngagement(t, ctx, pool, tenantA, assessmentID, "", "")
	ensureTestTenantAndEngagement(t, ctx, pool, tenantB, shared.ID(fmt.Sprintf("snapshot-other-%d", suffix)), "", "")

	cycleRepository := NewAssessmentCycleRepository(pool)
	cycle, err := assessmentcycle.NewAssessmentCycle(cycleID, tenantA, "Snapshot cycle", assessmentcycle.BoundaryStandalone, "", "", assessmentID, "operator", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	member, err := assessmentcycle.NewInitialMember(tenantA, cycleID, assessmentID, "operator", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := cycleRepository.CreateCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	if err := cycleRepository.CreateMember(ctx, member); err != nil {
		t.Fatal(err)
	}

	runRepository := NewScanRunStore(pool)
	runOne := postgresNativeRun(t, tenantA, assessmentID, shared.ID(fmt.Sprintf("snapshot-run-1-%d", suffix)), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err := runRepository.Begin(ctx, beginningPostgresScanRun(runOne)); err != nil {
		t.Fatal(err)
	}
	if err := runOne.Seal(scanrun.StatusSucceeded, 1, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := runRepository.Seal(ctx, runOne); err != nil {
		t.Fatal(err)
	}

	repository := NewAssessmentSnapshotRepository(pool)
	first := postgresAssessmentSnapshot(t, tenantA, cycleID, assessmentID, "snapshot-first", "request-first", runOne)
	stored, created, err := repository.CreateFinalizedCAS(ctx, first, 0)
	if err != nil || !created || stored.SnapshotNumber != 1 {
		t.Fatalf("create first snapshot=%+v created=%v err=%v", stored, created, err)
	}
	replayed, created, err := repository.CreateFinalizedCAS(ctx, postgresAssessmentSnapshot(t, tenantA, cycleID, assessmentID, "snapshot-replay", "request-first", runOne), 0)
	if err != nil || created || replayed.ID != stored.ID {
		t.Fatalf("replay snapshot=%+v created=%v err=%v", replayed, created, err)
	}
	if _, err := repository.Get(ctx, tenantB, stored.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get=%v", err)
	}

	runTwo := postgresNativeRun(t, tenantA, assessmentID, shared.ID(fmt.Sprintf("snapshot-run-2-%d", suffix)), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err := runRepository.Begin(ctx, beginningPostgresScanRun(runTwo)); err != nil {
		t.Fatal(err)
	}
	if err := runTwo.Seal(scanrun.StatusSucceeded, 1, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := runRepository.Seal(ctx, runTwo); err != nil {
		t.Fatal(err)
	}
	second := postgresAssessmentSnapshot(t, tenantA, cycleID, assessmentID, "snapshot-second", "request-second", runTwo)
	storedSecond, created, err := repository.CreateFinalizedCAS(ctx, second, 1)
	if err != nil || !created || storedSecond.SnapshotNumber != 2 {
		t.Fatalf("create second snapshot=%+v created=%v err=%v", storedSecond, created, err)
	}
	old, err := repository.Get(ctx, tenantA, stored.ID)
	if err != nil || old.Lifecycle != assessmentsnapshot.LifecycleSuperseded {
		t.Fatalf("superseded snapshot=%+v err=%v", old, err)
	}
	if _, _, err := repository.CreateFinalizedCAS(ctx, postgresAssessmentSnapshot(t, tenantA, cycleID, assessmentID, "snapshot-stale", "request-stale", runOne), 1); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale default CAS=%v", err)
	}

	if err := WithTenant(ctx, pool, tenantA.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE assessment_snapshots SET content_hash=$1 WHERE tenant_id=$2 AND id=$3`,
			"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", tenantA.String(), storedSecond.ID.String())
		return err
	}); err == nil {
		t.Fatal("finalized snapshot accepted content mutation")
	}

	for _, table := range []string{"assessment_snapshots", "assessment_snapshot_run_refs", "assessment_snapshot_lane_refs", "assessment_snapshot_dimensions", "assessment_snapshot_counters", "assessment_snapshot_defaults"} {
		var forced bool
		if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&forced); err != nil || !forced {
			t.Fatalf("FORCE RLS %s=%v err=%v", table, forced, err)
		}
	}
}

func TestPostgresAssessmentSnapshotRepositoryConcurrentInitialCASHasNoNumberGap(t *testing.T) {
	ctx, pool := setupTestDB(t)
	suffix := time.Now().UnixNano()
	tenantID := shared.ID(fmt.Sprintf("snapshot-concurrent-tenant-%d", suffix))
	assessmentID := shared.ID(fmt.Sprintf("snapshot-concurrent-assessment-%d", suffix))
	cycleID := shared.ID(fmt.Sprintf("snapshot-concurrent-cycle-%d", suffix))
	ensureTestTenantAndEngagement(t, ctx, pool, tenantID, assessmentID, "", "")

	cycleRepository := NewAssessmentCycleRepository(pool)
	cycle, err := assessmentcycle.NewAssessmentCycle(cycleID, tenantID, "Concurrent snapshot cycle", assessmentcycle.BoundaryStandalone, "", "", assessmentID, "operator", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	member, err := assessmentcycle.NewInitialMember(tenantID, cycleID, assessmentID, "operator", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := cycleRepository.CreateCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	if err := cycleRepository.CreateMember(ctx, member); err != nil {
		t.Fatal(err)
	}

	runRepository := NewScanRunStore(pool)
	run := postgresNativeRun(t, tenantID, assessmentID, shared.ID(fmt.Sprintf("snapshot-concurrent-run-%d", suffix)), "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	if err := runRepository.Begin(ctx, beginningPostgresScanRun(run)); err != nil {
		t.Fatal(err)
	}
	if err := run.Seal(scanrun.StatusSucceeded, 1, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := runRepository.Seal(ctx, run); err != nil {
		t.Fatal(err)
	}

	repository := NewAssessmentSnapshotRepository(pool)
	candidates := []*assessmentsnapshot.Snapshot{
		postgresAssessmentSnapshot(t, tenantID, cycleID, assessmentID, fmt.Sprintf("snapshot-concurrent-a-%d", suffix), "request-a", run),
		postgresAssessmentSnapshot(t, tenantID, cycleID, assessmentID, fmt.Sprintf("snapshot-concurrent-b-%d", suffix), "request-b", run),
	}
	type result struct {
		snapshot *assessmentsnapshot.Snapshot
		created  bool
		err      error
	}
	start := make(chan struct{})
	results := make(chan result, len(candidates))
	var wait sync.WaitGroup
	for _, candidate := range candidates {
		wait.Add(1)
		go func(candidate *assessmentsnapshot.Snapshot) {
			defer wait.Done()
			<-start
			stored, created, err := repository.CreateFinalizedCAS(ctx, candidate, 0)
			results <- result{snapshot: stored, created: created, err: err}
		}(candidate)
	}
	close(start)
	wait.Wait()
	close(results)

	var winner *assessmentsnapshot.Snapshot
	var successes, conflicts int
	for result := range results {
		switch {
		case result.err == nil && result.created:
			successes++
			winner = result.snapshot
		case errors.Is(result.err, shared.ErrConflict):
			conflicts++
		default:
			t.Fatalf("concurrent initial CAS result=%+v", result)
		}
	}
	if successes != 1 || conflicts != 1 || winner == nil || winner.SnapshotNumber != 1 {
		t.Fatalf("concurrent initial CAS successes=%d conflicts=%d winner=%+v", successes, conflicts, winner)
	}
	defaultSnapshot, pointer, err := repository.GetDefault(ctx, tenantID, assessmentID)
	if err != nil || pointer.Version != 1 || defaultSnapshot.ID != winner.ID {
		t.Fatalf("default snapshot=%+v pointer=%+v err=%v", defaultSnapshot, pointer, err)
	}
	snapshots, err := repository.ListByAssessment(ctx, tenantID, assessmentID)
	if err != nil || len(snapshots) != 1 || snapshots[0].SnapshotNumber != 1 {
		t.Fatalf("snapshots=%+v err=%v", snapshots, err)
	}
}

func TestPostgresAssessmentSnapshotConcurrentReplayAndAuditRollback(t *testing.T) {
	ctx, pool := setupTestDB(t)
	suffix := time.Now().UnixNano()
	tenantID, assessmentID, cycleID, run := createPostgresSnapshotFixture(t, ctx, pool, fmt.Sprintf("replay-%d", suffix))
	repository := NewAssessmentSnapshotRepository(pool)
	candidate := postgresAssessmentSnapshot(t, tenantID, cycleID, assessmentID, fmt.Sprintf("snapshot-replay-%d", suffix), "request-replay", run)

	type result struct {
		snapshot *assessmentsnapshot.Snapshot
		created  bool
		err      error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var wait sync.WaitGroup
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			stored, created, err := repository.CreateFinalizedCAS(context.Background(), candidate, 0)
			results <- result{snapshot: stored, created: created, err: err}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	var createdCount, replayCount int
	for result := range results {
		if result.err != nil || result.snapshot == nil || result.snapshot.ID != candidate.ID {
			t.Fatalf("concurrent replay result=%+v", result)
		}
		if result.created {
			createdCount++
		} else {
			replayCount++
		}
	}
	if createdCount != 1 || replayCount != 1 {
		t.Fatalf("concurrent replay created=%d replayed=%d", createdCount, replayCount)
	}

	failureTenant, failureAssessment, _, failureRun := createPostgresSnapshotFixture(t, ctx, pool, fmt.Sprintf("rollback-%d", suffix))
	failureRepository := NewAssessmentSnapshotRepository(pool)
	service, err := snapshotuc.NewService(
		failureRepository, NewAssessmentCycleRepository(pool), NewEngagementRepository(pool), NewScanRunStore(pool), NewTenantTransactionRunner(pool),
		&postgresLineageIDs{prefix: fmt.Sprintf("snapshot-rollback-%d", suffix)},
		postgresLineageClock{now: time.Date(2026, time.September, 1, 15, 0, 0, 0, time.UTC)}, snapshotFailureAudit{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.Finalize(ctx, snapshotuc.FinalizeInput{
		TenantID: failureTenant, AssessmentID: failureAssessment, SelectedRunIDs: []string{failureRun.ID},
		RequestKey: "request-audit-failure", ExpectedDefaultVersion: 0, Actor: "operator",
	}); err == nil || !strings.Contains(err.Error(), "forced snapshot audit failure") {
		t.Fatalf("audit failure=%v", err)
	}
	if _, err := failureRepository.GetByRequestKey(ctx, failureTenant, failureAssessment, "request-audit-failure"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("audit failure retained snapshot=%v", err)
	}
	if snapshots, err := failureRepository.ListByAssessment(ctx, failureTenant, failureAssessment); err != nil || len(snapshots) != 0 {
		t.Fatalf("audit rollback snapshots=%+v err=%v", snapshots, err)
	}
}

func createPostgresSnapshotFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) (shared.ID, shared.ID, shared.ID, ports.ScanRun) {
	t.Helper()
	tenantID := shared.ID("snapshot-service-tenant-" + suffix)
	assessmentID := shared.ID("snapshot-service-assessment-" + suffix)
	cycleID := shared.ID("snapshot-service-cycle-" + suffix)
	ensureTestTenantAndEngagement(t, ctx, pool, tenantID, assessmentID, "", "")
	cycle, err := assessmentcycle.NewAssessmentCycle(cycleID, tenantID, "Snapshot service cycle", assessmentcycle.BoundaryStandalone, "", "", assessmentID, "operator", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	member, err := assessmentcycle.NewInitialMember(tenantID, cycleID, assessmentID, "operator", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	cycles := NewAssessmentCycleRepository(pool)
	if err := cycles.CreateCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	if err := cycles.CreateMember(ctx, member); err != nil {
		t.Fatal(err)
	}
	run := postgresNativeRun(t, tenantID, assessmentID, shared.ID("snapshot-service-run-"+suffix), strings.Repeat("e", 64))
	runs := NewScanRunStore(pool)
	if err := runs.Begin(ctx, beginningPostgresScanRun(run)); err != nil {
		t.Fatal(err)
	}
	if err := run.Seal(scanrun.StatusSucceeded, 1, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := runs.Seal(ctx, run); err != nil {
		t.Fatal(err)
	}
	return tenantID, assessmentID, cycleID, run
}

type snapshotFailureAudit struct{}

func (snapshotFailureAudit) Record(context.Context, ports.AuditEntry) error {
	return errors.New("forced snapshot audit failure")
}

func postgresAssessmentSnapshot(t *testing.T, tenantID, cycleID, assessmentID shared.ID, snapshotID, requestKey string, run ports.ScanRun) *assessmentsnapshot.Snapshot {
	t.Helper()
	if err := run.ValidateSealed(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := assessmentsnapshot.NewFinalized(tenantID, shared.ID(snapshotID), cycleID, assessmentID,
		assessmentsnapshot.Boundary{Kind: assessmentcycle.BoundaryStandalone}, requestKey, "operator", time.Now().UTC(),
		[]assessmentsnapshot.SelectedRun{{
			ID: run.ID, ManifestHash: run.ManifestHash, Provenance: run.Provenance,
			TerminalStatus: run.TerminalStatus, Trusted: true, Lanes: run.Lanes,
		}})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
