package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	snapshotuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestPostgresAssessmentSnapshotBackfillRunnerAndRLS(t *testing.T) {
	db, dsn := newMigration0140DB(t)
	if err := goose.UpTo(db, ".", 148); err != nil {
		t.Fatalf("up to 0148: %v", err)
	}
	ctx := context.Background()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	now := time.Now().UTC().Add(time.Hour)
	clock := &postgresBackfillClock{now: now}
	tenantID, otherTenantID := shared.ID("snapshot-backfill-pg"), shared.ID("snapshot-backfill-other")
	assessmentID, otherAssessmentID := shared.ID("snapshot-backfill-assessment"), shared.ID("snapshot-backfill-other-assessment")
	ensureTestTenantAndEngagement(t, ctx, pool, tenantID, assessmentID, "", "")
	ensureTestTenantAndEngagement(t, ctx, pool, otherTenantID, otherAssessmentID, "", "")
	cycles := NewAssessmentCycleRepository(pool)
	cycle, err := assessmentcycle.NewAssessmentCycle("snapshot-backfill-cycle", tenantID, "Cycle", assessmentcycle.BoundaryStandalone, "", "", assessmentID, "operator", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	member, err := assessmentcycle.NewInitialMember(tenantID, cycle.ID, assessmentID, "operator", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := cycles.CreateCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	if err := cycles.CreateMember(ctx, member); err != nil {
		t.Fatal(err)
	}
	run := postgresNativeRun(t, tenantID, assessmentID, "snapshot-backfill-run", strings.Repeat("a", 64))
	runRepository := NewScanRunStore(pool)
	if err := runRepository.Begin(ctx, beginningPostgresScanRun(run)); err != nil {
		t.Fatal(err)
	}
	if err := run.Seal(scanrun.StatusSucceeded, 1, now); err != nil {
		t.Fatal(err)
	}
	if err := runRepository.Seal(ctx, run); err != nil {
		t.Fatal(err)
	}
	storedRuns, err := runRepository.List(ctx, tenantID, assessmentID)
	if err != nil || len(storedRuns) != 1 {
		t.Fatalf("stored runs=%+v err=%v", storedRuns, err)
	}
	if err := storedRuns[0].ValidateSealed(); err != nil {
		t.Fatalf("stored sealed run validation=%v run=%+v", err, storedRuns[0])
	}
	results := NewScanResultStore(pool)
	if err := results.SaveResult(ctx, assessmentID, []byte(`{"source":"legacy-cache"}`)); err != nil {
		t.Fatal(err)
	}
	snapshots := NewAssessmentSnapshotRepository(pool)
	audit := NewAuditLog(pool)
	projector, err := snapshotuc.NewLegacyProjector(snapshots, cycles, NewTenantTransactionRunner(pool), idgen.RandomID{}, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	store := NewAssessmentSnapshotBackfillRepository(pool)
	runner, err := snapshotuc.NewBackfillRunner(projector, NewEngagementRepository(pool), store, runRepository, results, idgen.RandomID{}, clock, audit, nil)
	if err != nil {
		t.Fatal(err)
	}
	backfillRun, err := runner.Run(ctx, snapshotuc.BackfillRequest{TenantID: tenantID, Actor: "operator", LeaseOwner: "postgres", BatchSize: 1})
	if err != nil || backfillRun.State != ports.AssessmentSnapshotBackfillCompleted || backfillRun.CreatedCount != 1 || backfillRun.FailedCount != 0 {
		item, itemErr := store.GetAssessmentSnapshotBackfillItem(ctx, tenantID, backfillRun.ID, assessmentID)
		t.Fatalf("postgres snapshot backfill=%+v item=%+v item_err=%v err=%v", backfillRun, item, itemErr, err)
	}
	projected, err := snapshots.ListByAssessment(ctx, tenantID, assessmentID)
	if err != nil || len(projected) != 1 || projected[0].Provenance != assessmentsnapshot.ProvenanceLegacy || len(projected[0].Dimensions) != 1 || projected[0].Dimensions[0].State != assessmentsnapshot.CoverageUnknown {
		t.Fatalf("postgres projected snapshots=%+v err=%v", projected, err)
	}
	if _, _, err := snapshots.GetDefault(ctx, tenantID, assessmentID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("legacy projection changed default: %v", err)
	}
	if _, err := store.GetAssessmentSnapshotBackfillRun(ctx, otherTenantID, backfillRun.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant run read=%v", err)
	}
	if _, err := store.GetAssessmentSnapshotBackfillItem(ctx, otherTenantID, backfillRun.ID, assessmentID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant item read=%v", err)
	}
}

func TestPostgresAssessmentSnapshotBackfillLeaseAndCompositeOwnership(t *testing.T) {
	db, dsn := newMigration0140DB(t)
	if err := goose.UpTo(db, ".", 148); err != nil {
		t.Fatalf("up to 0148: %v", err)
	}
	ctx := context.Background()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ensureTestTenantAndEngagement(t, ctx, pool, "snapshot-lease-a", "snapshot-assessment-a", "", "")
	ensureTestTenantAndEngagement(t, ctx, pool, "snapshot-lease-b", "snapshot-assessment-b", "", "")
	repository := NewAssessmentSnapshotBackfillRepository(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	request := ports.AssessmentSnapshotBackfillAcquireRequest{Run: ports.AssessmentSnapshotBackfillRun{
		TenantID: "snapshot-lease-a", ID: "run-a", SchemaVersion: 1, BatchSize: 500, SnapshotAt: now,
		State: ports.AssessmentSnapshotBackfillRunning, LeaseOwner: "owner-a", LeaseExpiresAt: now.Add(time.Minute), CreatedBy: "operator", CreatedAt: now, UpdatedAt: now,
	}, LeaseDuration: time.Minute}
	if _, _, err := repository.AcquireAssessmentSnapshotBackfillRun(ctx, request); err != nil {
		t.Fatal(err)
	}
	contender := request
	contender.Run.ID, contender.Run.LeaseOwner = "run-b", "owner-b"
	if _, _, err := repository.AcquireAssessmentSnapshotBackfillRun(ctx, contender); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("concurrent lease=%v", err)
	}
	if _, err := repository.SaveAssessmentSnapshotBackfillItem(ctx, ports.AssessmentSnapshotBackfillItem{
		TenantID: "snapshot-lease-a", RunID: "run-a", AssessmentID: "snapshot-assessment-b", SchemaVersion: 1,
		IdempotencyKey: "source-v1", SourceHash: strings.Repeat("a", 64), Outcome: "failed", ReasonCode: "source_read_failed", ProcessedAt: now,
	}); err == nil {
		t.Fatal("expected cross-tenant Assessment ownership rejection")
	}
	contender.Run.CreatedAt, contender.Run.SnapshotAt = now.Add(2*time.Minute), now
	resumed, wasResumed, err := repository.AcquireAssessmentSnapshotBackfillRun(ctx, contender)
	if err != nil || !wasResumed || resumed.ID != "run-a" || resumed.LeaseOwner != "owner-b" {
		t.Fatalf("expired lease resume=%+v resumed=%v err=%v", resumed, wasResumed, err)
	}
}

func TestPostgresAssessmentSnapshotBackfillConcurrentStart(t *testing.T) {
	db, dsn := newMigration0140DB(t)
	if err := goose.UpTo(db, ".", 148); err != nil {
		t.Fatalf("up to 0148: %v", err)
	}
	ctx := context.Background()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('snapshot-concurrent','Snapshot concurrent')`); err != nil {
		t.Fatal(err)
	}
	repository := NewAssessmentSnapshotBackfillRepository(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	start := make(chan struct{})
	errorsCh := make(chan error, 2)
	var wait sync.WaitGroup
	for _, identity := range []string{"a", "b"} {
		wait.Add(1)
		go func(identity string) {
			defer wait.Done()
			<-start
			_, _, err := repository.AcquireAssessmentSnapshotBackfillRun(ctx, ports.AssessmentSnapshotBackfillAcquireRequest{Run: ports.AssessmentSnapshotBackfillRun{
				TenantID: "snapshot-concurrent", ID: shared.ID("run-" + identity), SchemaVersion: 1, BatchSize: 500, SnapshotAt: now,
				State: ports.AssessmentSnapshotBackfillRunning, LeaseOwner: "owner-" + identity, LeaseExpiresAt: now.Add(time.Minute), CreatedBy: "operator", CreatedAt: now, UpdatedAt: now,
			}, LeaseDuration: time.Minute})
			errorsCh <- err
		}(identity)
	}
	close(start)
	wait.Wait()
	close(errorsCh)
	succeeded, conflicted := 0, 0
	for err := range errorsCh {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, shared.ErrConflict):
			conflicted++
		default:
			t.Fatalf("concurrent start error=%v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent starts succeeded=%d conflicted=%d", succeeded, conflicted)
	}
}

func TestPostgresAssessmentSnapshotBackfillProjectsUpgradedLegacyRun(t *testing.T) {
	db, dsn := newMigration0140DB(t)
	if err := goose.UpTo(db, ".", 128); err != nil {
		t.Fatalf("up to 0128: %v", err)
	}
	for _, statement := range []string{
		`INSERT INTO tenants(id,name) VALUES('snapshot-upgrade-tenant','Snapshot upgrade')`,
		`INSERT INTO engagements(id,tenant_id,name,created_at,updated_at) VALUES('snapshot-upgrade-assessment','snapshot-upgrade-tenant','Historical',now()-interval '2 hours',now()-interval '1 hour')`,
		`INSERT INTO scan_runs(id,engagement_id,created_at,manifest,finding_keys) VALUES('snapshot-upgrade-run','snapshot-upgrade-assessment',now()-interval '1 hour','{}'::jsonb,'["legacy-key"]'::jsonb)`,
	} {
		if _, err := db.ExecContext(context.Background(), statement); err != nil {
			t.Fatalf("seed upgraded legacy fixture: %v", err)
		}
	}
	if err := goose.UpTo(db, ".", 148); err != nil {
		t.Fatalf("upgrade fixture to 0148: %v", err)
	}
	ctx := context.Background()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tenantID, assessmentID := shared.ID("snapshot-upgrade-tenant"), shared.ID("snapshot-upgrade-assessment")
	cycles := NewAssessmentCycleRepository(pool)
	now := time.Now().UTC()
	cycle, err := assessmentcycle.NewAssessmentCycle("snapshot-upgrade-cycle", tenantID, "Cycle", assessmentcycle.BoundaryStandalone, "", "", assessmentID, "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	member, err := assessmentcycle.NewInitialMember(tenantID, cycle.ID, assessmentID, "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := cycles.CreateCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	if err := cycles.CreateMember(ctx, member); err != nil {
		t.Fatal(err)
	}
	clock := &postgresBackfillClock{now: now.Add(time.Minute)}
	snapshots := NewAssessmentSnapshotRepository(pool)
	audit := NewAuditLog(pool)
	projector, err := snapshotuc.NewLegacyProjector(snapshots, cycles, NewTenantTransactionRunner(pool), idgen.RandomID{}, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := snapshotuc.NewBackfillRunner(projector, NewEngagementRepository(pool), NewAssessmentSnapshotBackfillRepository(pool), NewScanRunStore(pool), NewScanResultStore(pool), idgen.RandomID{}, clock, audit, nil)
	if err != nil {
		t.Fatal(err)
	}
	run, err := runner.Run(ctx, snapshotuc.BackfillRequest{TenantID: tenantID, Actor: "operator", LeaseOwner: "upgrade", BatchSize: 1})
	if err != nil || run.CreatedCount != 1 {
		t.Fatalf("upgraded legacy projection run=%+v err=%v", run, err)
	}
	projected, err := snapshots.ListByAssessment(ctx, tenantID, assessmentID)
	if err != nil || len(projected) != 1 || projected[0].Provenance != assessmentsnapshot.ProvenanceLegacy || len(projected[0].RunReferences) != 1 || len(projected[0].Dimensions) != 0 {
		t.Fatalf("upgraded legacy projection=%+v err=%v", projected, err)
	}
}
