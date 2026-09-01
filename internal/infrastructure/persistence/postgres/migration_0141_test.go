package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestMigration0141EmptyRoundTrip(t *testing.T) {
	db, _ := newMigration0140DB(t)
	if err := goose.UpTo(db, ".", 141); err != nil {
		t.Fatalf("up to 0141: %v", err)
	}
	if err := goose.DownTo(db, ".", 140); err != nil {
		t.Fatalf("empty rollback to 0140: %v", err)
	}
	var exists bool
	if err := db.QueryRowContext(context.Background(), `SELECT to_regclass('public.assessment_snapshots') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Fatalf("assessment_snapshots after rollback exists=%v err=%v", exists, err)
	}
	if err := goose.UpTo(db, ".", 141); err != nil {
		t.Fatalf("reapply 0141: %v", err)
	}
}

func TestMigration0141UpgradeFixtureAndRollbackGuard(t *testing.T) {
	ctx := context.Background()
	db, dsn := newMigration0140DB(t)
	if err := goose.UpTo(db, ".", 140); err != nil {
		t.Fatalf("up to 0140: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := shared.ID("m141-tenant")
	assessmentID := shared.ID("m141-assessment")
	cycleID := shared.ID("m141-cycle")
	ensureTestTenantAndEngagement(t, ctx, pool, tenantID, assessmentID, "", "")
	cycle, err := assessmentcycle.NewAssessmentCycle(cycleID, tenantID, "Migration 141 cycle", assessmentcycle.BoundaryStandalone, "", "", assessmentID, "operator", time.Now().UTC())
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	member, err := assessmentcycle.NewInitialMember(tenantID, cycleID, assessmentID, "operator", time.Now().UTC())
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	cycleRepository := NewAssessmentCycleRepository(pool)
	if err := cycleRepository.CreateCycle(ctx, cycle); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	if err := cycleRepository.CreateMember(ctx, member); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	run := postgresNativeRun(t, tenantID, assessmentID, "m141-run", strings.Repeat("e", 64))
	runRepository := NewScanRunStore(pool)
	if err := runRepository.Begin(ctx, beginningPostgresScanRun(run)); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	if err := run.Seal(scanrun.StatusSucceeded, 1, time.Now().UTC()); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	if err := runRepository.Seal(ctx, run); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	pool.Close()

	if err := goose.UpTo(db, ".", 141); err != nil {
		t.Fatalf("upgrade fixture to 0141: %v", err)
	}
	pool, err = Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := postgresAssessmentSnapshot(t, tenantID, cycleID, assessmentID, "m141-snapshot", "m141-request", run)
	stored, created, err := NewAssessmentSnapshotRepository(pool).CreateFinalizedCAS(ctx, snapshot, 0)
	pool.Close()
	if err != nil || !created || stored.SnapshotNumber != 1 {
		t.Fatalf("create snapshot after upgrade=%+v created=%v err=%v", stored, created, err)
	}
	if err := goose.DownTo(db, ".", 140); err == nil || !strings.Contains(err.Error(), "cannot roll back assessment snapshots while snapshot rows exist") {
		t.Fatalf("rollback with snapshot rows error=%v", err)
	}
	var exists bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('public.assessment_snapshots') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		t.Fatalf("assessment_snapshots after refused rollback exists=%v err=%v", exists, err)
	}
}
