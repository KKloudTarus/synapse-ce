package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/platform/idgen"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/pressly/goose/v3"
)

func TestPostgresAssessmentCycleIntegrityVerifierFindsCorruption(t *testing.T) {
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 133); err != nil {
		t.Fatalf("up to 0133: %v", err)
	}
	ctx := context.Background()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	clock := &postgresBackfillClock{now: now}
	tenantID, otherTenantID := shared.ID("integrity-pg-tenant"), shared.ID("integrity-pg-other")
	for _, tenant := range []shared.ID{tenantID, otherTenantID} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant.String()); err != nil {
			t.Fatal(err)
		}
	}
	engagements := NewEngagementRepository(pool)
	for _, assessmentID := range []shared.ID{"assessment-a", "assessment-b"} {
		assessment, err := engdom.New(assessmentID, tenantID, assessmentID.String(), "Client", now.Add(-time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		assessment.Audit.CreatedBy, assessment.Audit.UpdatedBy = "owner", "owner"
		if err := engagements.Create(ctx, assessment); err != nil {
			t.Fatal(err)
		}
	}
	cycles := NewAssessmentCycleRepository(pool)
	cycleService, err := cycleuc.NewService(cycles, engagements, nil, nil, NewTenantTransactionRunner(pool), idgen.RandomID{}, clock, assessmentCycleNoopAudit{})
	if err != nil {
		t.Fatal(err)
	}
	cycle, _, err := cycleService.CreateInitialCycle(ctx, cycleuc.CreateInitialCycleInput{TenantID: tenantID, Name: "Cycle", BoundaryKind: cycledom.BoundaryStandalone, RootAssessmentID: "assessment-a", Actor: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE assessment_cycles SET selected_head_assessment_id='assessment-b' WHERE tenant_id=$1 AND id=$2`, tenantID.String(), cycle.ID.String()); err != nil {
		t.Fatal(err)
	}
	repository := NewAssessmentCycleIntegrityRepository(pool)
	verifier, err := cycleuc.NewIntegrityVerifier(repository, repository, idgen.RandomID{}, clock, assessmentCycleNoopAudit{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	run, err := verifier.Run(ctx, cycleuc.IntegrityRequest{TenantID: tenantID, Actor: "operator", LeaseOwner: "postgres-integrity", BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if run.State != ports.AssessmentCycleIntegrityCompleted || run.ScannedCount != 2 || run.CleanCount != 0 || run.FindingCount < 2 {
		t.Fatalf("integrity run = %+v", run)
	}
	findings, err := repository.ListAssessmentCycleIntegrityFindings(ctx, tenantID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]bool{}
	for _, finding := range findings {
		reasons[finding.ReasonCode] = true
	}
	if !reasons[cycleuc.IntegrityCoverageMissing] || !reasons[cycleuc.IntegritySelectedHeadMissing] {
		t.Fatalf("integrity reasons = %v", reasons)
	}
	if _, err := repository.GetAssessmentCycleIntegrityRun(ctx, otherTenantID, run.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant integrity run read = %v", err)
	}
}

func TestPostgresAssessmentCycleIntegrityLease(t *testing.T) {
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 133); err != nil {
		t.Fatalf("up to 0133: %v", err)
	}
	ctx := context.Background()
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('integrity-lease','integrity-lease')`); err != nil {
		t.Fatal(err)
	}
	repository := NewAssessmentCycleIntegrityRepository(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	request := ports.AssessmentCycleIntegrityAcquireRequest{Run: ports.AssessmentCycleIntegrityRun{
		TenantID: "integrity-lease", ID: "run-a", BatchSize: 500, SnapshotAt: now, State: ports.AssessmentCycleIntegrityRunning,
		LeaseOwner: "owner-a", LeaseToken: "token-a", LeaseExpiresAt: now.Add(time.Minute), CreatedBy: "operator", CreatedAt: now, UpdatedAt: now,
	}, LeaseDuration: time.Minute}
	if _, _, err := repository.AcquireAssessmentCycleIntegrityRun(ctx, request); err != nil {
		t.Fatal(err)
	}
	contender := request
	contender.Run.ID, contender.Run.LeaseOwner, contender.Run.LeaseToken = "run-b", "owner-b", "token-b"
	if _, _, err := repository.AcquireAssessmentCycleIntegrityRun(ctx, contender); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("concurrent integrity lease = %v", err)
	}
	contender.Run.CreatedAt, contender.Run.SnapshotAt = now.Add(2*time.Minute), now
	resumed, wasResumed, err := repository.AcquireAssessmentCycleIntegrityRun(ctx, contender)
	if err != nil || !wasResumed || resumed.ID != "run-a" || resumed.LeaseOwner != "owner-b" {
		t.Fatalf("expired integrity lease resume = %+v resumed=%v err=%v", resumed, wasResumed, err)
	}
}
