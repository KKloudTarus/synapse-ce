package assessmentcycle_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestIntegrityVerifierPersistsFindingsAndResumesExpiredRun(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	clock := &mutableBackfillClock{now: now}
	ids := &seqIDGen{}
	audit := &recordAudit{}
	engagements := memory.NewEngagementRepository()
	cycles := memory.NewAssessmentCycleRepository()
	transactions := memory.NewTenantTransactionRunner()
	cycleService, err := cycleuc.NewService(cycles, engagements, nil, nil, transactions, ids, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := shared.ID("tenant-integrity")
	covered := addHistoricalAssessment(t, ctx, engagements, tenantID, "assessment-a", engdom.StatusActive, "", now.Add(-2*time.Hour), now.Add(-time.Hour), "owner", "owner")
	missing := addHistoricalAssessment(t, ctx, engagements, tenantID, "assessment-b", engdom.StatusActive, "", now.Add(-time.Hour), now.Add(-time.Hour), "owner", "owner")
	if _, _, err := cycleService.CreateInitialCycle(ctx, cycleuc.CreateInitialCycleInput{TenantID: tenantID, Name: covered.Name, BoundaryKind: cycledom.BoundaryStandalone, RootAssessmentID: covered.ID, Actor: "owner"}); err != nil {
		t.Fatal(err)
	}
	repository := memory.NewAssessmentCycleIntegrityRepository(engagements, cycles)
	verifier, err := cycleuc.NewIntegrityVerifier(repository, repository, ids, clock, audit, nil)
	if err != nil {
		t.Fatal(err)
	}
	run, err := verifier.Run(ctx, cycleuc.IntegrityRequest{TenantID: tenantID, Actor: "operator", LeaseOwner: "process-1", BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if run.State != ports.AssessmentCycleIntegrityCompleted || run.ScannedCount != 2 || run.CleanCount != 1 || run.FindingCount != 1 {
		t.Fatalf("integrity run = %+v", run)
	}
	findings, err := repository.ListAssessmentCycleIntegrityFindings(ctx, tenantID, run.ID)
	if err != nil || len(findings) != 1 || findings[0].AssessmentID != missing.ID || findings[0].ReasonCode != cycleuc.IntegrityCoverageMissing || !strings.Contains(string(findings[0].RepairPlan), "create_singleton_cycle") {
		t.Fatalf("integrity findings = %+v, err=%v", findings, err)
	}

	lease := time.Minute
	crashed, _, err := repository.AcquireAssessmentCycleIntegrityRun(ctx, ports.AssessmentCycleIntegrityAcquireRequest{Run: ports.AssessmentCycleIntegrityRun{
		TenantID: tenantID, ID: "integrity-crashed", BatchSize: 1, SnapshotAt: now, State: ports.AssessmentCycleIntegrityRunning,
		LeaseOwner: "dead", LeaseExpiresAt: now.Add(lease), CreatedBy: "operator", CreatedAt: now, UpdatedAt: now,
	}, LeaseDuration: lease})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Run(ctx, cycleuc.IntegrityRequest{TenantID: tenantID, Actor: "operator", LeaseOwner: "live", BatchSize: 1, LeaseDuration: lease}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("concurrent verifier = %v", err)
	}
	clock.Advance(lease + time.Second)
	resumed, err := verifier.Run(ctx, cycleuc.IntegrityRequest{TenantID: tenantID, Actor: "operator", LeaseOwner: "live", BatchSize: 1, LeaseDuration: lease})
	if err != nil || resumed.ID != crashed.ID || resumed.ScannedCount != 2 || resumed.FindingCount != 1 {
		t.Fatalf("resumed verifier = %+v, err=%v", resumed, err)
	}
}

func TestIntegrityVerifierRejectsOversizedBatch(t *testing.T) {
	clock := &mutableBackfillClock{now: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	repository := memory.NewAssessmentCycleIntegrityRepository(memory.NewEngagementRepository(), memory.NewAssessmentCycleRepository())
	verifier, err := cycleuc.NewIntegrityVerifier(repository, repository, &seqIDGen{}, clock, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Run(context.Background(), cycleuc.IntegrityRequest{TenantID: "tenant", Actor: "operator", LeaseOwner: "process", BatchSize: 2001}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("oversized batch = %v", err)
	}
}
