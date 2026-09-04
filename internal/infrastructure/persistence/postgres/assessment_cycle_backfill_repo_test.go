package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/pressly/goose/v3"
)

type postgresBackfillClock struct{ now time.Time }

func (clock *postgresBackfillClock) Now() time.Time { return clock.now }

func TestPostgresAssessmentCycleBackfillRunner(t *testing.T) {
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 132); err != nil {
		t.Fatalf("up to 0132: %v", err)
	}
	ctx := context.Background()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	clock := &postgresBackfillClock{now: now}
	tenantID, otherTenantID := shared.ID("backfill-pg-tenant"), shared.ID("backfill-pg-other")
	for _, tenant := range []shared.ID{tenantID, otherTenantID} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant.String()); err != nil {
			t.Fatal(err)
		}
	}
	engagements := NewEngagementRepository(pool)
	for index, status := range []engdom.Status{engdom.StatusActive, engdom.StatusArchived} {
		assessment, err := engdom.New(shared.ID([]string{"assessment-a", "assessment-b"}[index]), tenantID, "Historical", "Client", now.Add(-time.Duration(index+2)*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		assessment.Status = status
		assessment.Audit.CreatedBy, assessment.Audit.UpdatedBy = "owner", "reviewer"
		assessment.Audit.UpdatedAt = now.Add(-time.Duration(index+1) * time.Hour)
		if err := engagements.Create(ctx, assessment); err != nil {
			t.Fatal(err)
		}
	}
	cycles := NewAssessmentCycleRepository(pool)
	transactions := NewTenantTransactionRunner(pool)
	audit := assessmentCycleNoopAudit{}
	cycleService, err := cycleuc.NewService(cycles, engagements, nil, nil, transactions, idgen.RandomID{}, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	store := NewAssessmentCycleBackfillRepository(pool)
	runner, err := cycleuc.NewBackfillRunner(cycleService, engagements, store, idgen.RandomID{}, clock, audit, nil)
	if err != nil {
		t.Fatal(err)
	}
	run, err := runner.Run(ctx, cycleuc.BackfillRequest{TenantID: tenantID, Actor: "operator", LeaseOwner: "postgres-test", BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if run.State != ports.AssessmentCycleBackfillCompleted || run.ProcessedCount != 2 || run.CreatedCount != 2 || run.CheckpointAssessment != "assessment-b" {
		t.Fatalf("postgres backfill run = %+v", run)
	}
	if _, err := store.GetAssessmentCycleBackfillRun(ctx, otherTenantID, run.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant run read = %v", err)
	}
	archived, err := cycles.GetCycleByAssessment(ctx, tenantID, "assessment-b")
	if err != nil || archived.Status != "archived" || archived.CreatedBy != "owner" || archived.UpdatedBy != "reviewer" {
		t.Fatalf("postgres archived cycle = %+v, err=%v", archived, err)
	}
}

func TestPostgresAssessmentCycleBackfillLeaseAndCompositeFK(t *testing.T) {
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 132); err != nil {
		t.Fatalf("up to 0132: %v", err)
	}
	ctx := context.Background()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	for _, tenant := range []string{"lease-a", "lease-b"} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	assessment, err := engdom.New("assessment-b", "lease-b", "Other tenant", "Client", time.Now().UTC().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := NewEngagementRepository(pool).Create(ctx, assessment); err != nil {
		t.Fatal(err)
	}
	repository := NewAssessmentCycleBackfillRepository(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	request := ports.AssessmentCycleBackfillAcquireRequest{Run: ports.AssessmentCycleBackfillRun{
		TenantID: "lease-a", ID: "run-a", SchemaVersion: 1, BatchSize: 500, SnapshotAt: now, State: ports.AssessmentCycleBackfillRunning,
		LeaseOwner: "owner-a", LeaseToken: "token-a", LeaseExpiresAt: now.Add(time.Minute), CreatedBy: "operator", CreatedAt: now, UpdatedAt: now,
	}, LeaseDuration: time.Minute}
	if _, _, err := repository.AcquireAssessmentCycleBackfillRun(ctx, request); err != nil {
		t.Fatal(err)
	}
	contender := request
	contender.Run.ID, contender.Run.LeaseOwner, contender.Run.LeaseToken = "run-b", "owner-b", "token-b"
	if _, _, err := repository.AcquireAssessmentCycleBackfillRun(ctx, contender); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("concurrent backfill lease = %v", err)
	}
	if _, _, err := repository.CommitAssessmentCycleBackfillItem(ctx, "lease-a", "run-a", "token-a", now, func(context.Context) (ports.AssessmentCycleBackfillItem, error) {
		return ports.AssessmentCycleBackfillItem{TenantID: "lease-a", RunID: "run-a", AssessmentID: "assessment-b", SchemaVersion: 1, IdempotencyKey: "source-v1", Outcome: "failed", ReasonCode: "source_not_found", RepairGuidance: "repair", ProcessedAt: now}, nil
	}); err == nil {
		t.Fatal("expected composite tenant FK rejection")
	}
	contender.Run.CreatedAt, contender.Run.SnapshotAt = now.Add(2*time.Minute), now
	resumed, wasResumed, err := repository.AcquireAssessmentCycleBackfillRun(ctx, contender)
	if err != nil || !wasResumed || resumed.ID != "run-a" || resumed.LeaseOwner != "owner-b" {
		t.Fatalf("expired lease resume = %+v resumed=%v err=%v", resumed, wasResumed, err)
	}
}
