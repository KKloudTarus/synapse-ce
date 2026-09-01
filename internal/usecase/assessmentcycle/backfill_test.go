package assessmentcycle_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type mutableBackfillClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *mutableBackfillClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *mutableBackfillClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

type retryBackfiller struct {
	calls int
	fail  int
	err   error
}

func (backfiller *retryBackfiller) BackfillHistoricalSingleton(context.Context, cycleuc.BackfillHistoricalSingletonInput) (cycleuc.BackfillHistoricalSingletonResult, error) {
	backfiller.calls++
	if backfiller.calls <= backfiller.fail {
		return cycleuc.BackfillHistoricalSingletonResult{}, backfiller.err
	}
	return cycleuc.BackfillHistoricalSingletonResult{Created: true, CycleID: "cycle-retried", ReasonCode: cycleuc.BackfillReasonCreated}, nil
}

type backfillObserver struct {
	items []string
	runs  []string
}

func (observer *backfillObserver) ObserveAssessmentCycleBackfillItem(outcome string) {
	observer.items = append(observer.items, outcome)
}

func (observer *backfillObserver) ObserveAssessmentCycleBackfillRun(state string) {
	observer.runs = append(observer.runs, state)
}

func TestBackfillRunnerPreservesHistoryAndRerunsWithoutDuplicates(t *testing.T) {
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
	tenantID := shared.ID("tenant-backfill")
	existing := addHistoricalAssessment(t, ctx, engagements, tenantID, "assessment-a", engdom.StatusCompleted, "", now.Add(-72*time.Hour), now.Add(-48*time.Hour), "owner-a", "reviewer-a")
	archived := addHistoricalAssessment(t, ctx, engagements, tenantID, "assessment-b", engdom.StatusArchived, "", now.Add(-48*time.Hour), now.Add(-24*time.Hour), "owner-b", "reviewer-b")
	asset := addHistoricalAssessment(t, ctx, engagements, tenantID, "assessment-c", engdom.StatusActive, "asset-1", now.Add(-24*time.Hour), now.Add(-12*time.Hour), "owner-c", "owner-c")
	hidden := addHistoricalAssessment(t, ctx, engagements, tenantID, "assessment-hidden", engdom.StatusActive, "", now.Add(-time.Hour), now.Add(-time.Hour), "owner-hidden", "owner-hidden")
	hidden.ProjectID = "project-1"
	if err := engagements.Update(ctx, hidden); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cycleService.CreateInitialCycle(ctx, cycleuc.CreateInitialCycleInput{TenantID: tenantID, Name: existing.Name, BoundaryKind: cycledom.BoundaryStandalone, RootAssessmentID: existing.ID, Actor: "owner-a"}); err != nil {
		t.Fatal(err)
	}

	store := memory.NewAssessmentCycleBackfillRepository()
	observer := &backfillObserver{}
	runner, err := cycleuc.NewBackfillRunner(cycleService, engagements, store, ids, clock, audit, observer)
	if err != nil {
		t.Fatal(err)
	}
	first, err := runner.Run(ctx, cycleuc.BackfillRequest{TenantID: tenantID, Actor: "operator", LeaseOwner: "process-1", BatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if first.State != ports.AssessmentCycleBackfillCompleted || first.ProcessedCount != 3 || first.CreatedCount != 2 || first.SkippedCount != 1 || first.FailedCount != 0 {
		t.Fatalf("first backfill = %+v", first)
	}
	archivedCycle, err := cycles.GetCycleByAssessment(ctx, tenantID, archived.ID)
	if err != nil {
		t.Fatal(err)
	}
	if archivedCycle.Status != cycledom.StatusArchived || !archivedCycle.CreatedAt.Equal(archived.Audit.CreatedAt) || !archivedCycle.UpdatedAt.Equal(archived.Audit.UpdatedAt) || archivedCycle.CreatedBy != "owner-b" || archivedCycle.UpdatedBy != "reviewer-b" {
		t.Fatalf("archived history was not preserved: %+v", archivedCycle)
	}
	assetCycle, err := cycles.GetCycleByAssessment(ctx, tenantID, asset.ID)
	if err != nil || assetCycle.BoundaryKind != cycledom.BoundaryAsset || assetCycle.BusinessAssetID != "asset-1" {
		t.Fatalf("asset boundary backfill = %+v, err=%v", assetCycle, err)
	}
	if _, err := cycles.GetCycleByAssessment(ctx, tenantID, hidden.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("hidden Project context entered a Cycle: %v", err)
	}

	second, err := runner.Run(ctx, cycleuc.BackfillRequest{TenantID: tenantID, Actor: "operator", LeaseOwner: "process-2", BatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if second.CreatedCount != 0 || second.SkippedCount != 3 || len(observer.runs) != 2 {
		t.Fatalf("rerun = %+v observer=%+v", second, observer)
	}
	records, err := cycles.ListCycles(ctx, ports.AssessmentCycleListQuery{TenantID: tenantID, Limit: 10})
	if err != nil || len(records) != 3 {
		t.Fatalf("cycle count after rerun = %d, err=%v", len(records), err)
	}
}

func TestBackfillRunnerDryRunLeaseAndCrashResume(t *testing.T) {
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
	tenantID := shared.ID("tenant-resume")
	assessment := addHistoricalAssessment(t, ctx, engagements, tenantID, "assessment-a", engdom.StatusActive, "", now.Add(-time.Hour), now.Add(-time.Hour), "owner", "owner")
	store := memory.NewAssessmentCycleBackfillRepository()
	runner, err := cycleuc.NewBackfillRunner(cycleService, engagements, store, ids, clock, audit, nil)
	if err != nil {
		t.Fatal(err)
	}
	dryRun, err := runner.Run(ctx, cycleuc.BackfillRequest{TenantID: tenantID, Actor: "operator", LeaseOwner: "dry-run", DryRun: true, BatchSize: 1})
	if err != nil || dryRun.WouldCreateCount != 1 {
		t.Fatalf("dry run = %+v, err=%v", dryRun, err)
	}
	if _, err := cycles.GetCycleByAssessment(ctx, tenantID, assessment.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("dry run created a Cycle: %v", err)
	}

	lease := time.Minute
	crashed, _, err := store.AcquireAssessmentCycleBackfillRun(ctx, ports.AssessmentCycleBackfillAcquireRequest{Run: ports.AssessmentCycleBackfillRun{
		TenantID: tenantID, ID: "crashed-run", SchemaVersion: cycleuc.AssessmentCycleBackfillSchemaVersion, BatchSize: 1,
		SnapshotAt: now, State: ports.AssessmentCycleBackfillRunning, LeaseOwner: "dead-process", LeaseExpiresAt: now.Add(lease), CreatedBy: "operator", CreatedAt: now, UpdatedAt: now,
	}, LeaseDuration: lease})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(ctx, cycleuc.BackfillRequest{TenantID: tenantID, Actor: "operator", LeaseOwner: "live-process", BatchSize: 1, LeaseDuration: lease}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("concurrent lease = %v", err)
	}
	clock.Advance(lease + time.Second)
	resumed, err := runner.Run(ctx, cycleuc.BackfillRequest{TenantID: tenantID, Actor: "operator", LeaseOwner: "live-process", BatchSize: 1, LeaseDuration: lease})
	if err != nil || resumed.ID != crashed.ID || resumed.CreatedCount != 1 {
		t.Fatalf("crash resume = %+v, err=%v", resumed, err)
	}
}

func TestBackfillRunnerBoundsRetriesAndRedactsFailures(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	clock := &mutableBackfillClock{now: now}
	ids := &seqIDGen{}
	engagements := memory.NewEngagementRepository()
	tenantID := shared.ID("tenant-retry")
	assessment := addHistoricalAssessment(t, ctx, engagements, tenantID, "assessment-a", engdom.StatusActive, "", now.Add(-time.Hour), now.Add(-time.Hour), "owner", "owner")
	store := memory.NewAssessmentCycleBackfillRepository()
	backfiller := &retryBackfiller{fail: 3, err: errors.New("database unavailable: secret-token")}
	runner, err := cycleuc.NewBackfillRunner(backfiller, engagements, store, ids, clock, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	run, err := runner.Run(ctx, cycleuc.BackfillRequest{TenantID: tenantID, Actor: "operator", LeaseOwner: "process", BatchSize: 1})
	if err != nil || run.FailedCount != 1 || backfiller.calls != 3 {
		t.Fatalf("bounded retry run = %+v calls=%d err=%v", run, backfiller.calls, err)
	}
	item, err := store.GetAssessmentCycleBackfillItem(ctx, tenantID, run.ID, assessment.ID)
	if err != nil || item.ReasonCode != cycleuc.BackfillReasonWriteFailed || !item.Retryable || strings.Contains(item.RepairGuidance, "secret-token") {
		t.Fatalf("failure item = %+v, err=%v", item, err)
	}
}

func addHistoricalAssessment(t *testing.T, ctx context.Context, repository *memory.EngagementRepository, tenantID, assessmentID shared.ID, status engdom.Status, assetID shared.ID, createdAt, updatedAt time.Time, createdBy, updatedBy string) *engdom.Engagement {
	t.Helper()
	assessment, err := engdom.New(assessmentID, tenantID, assessmentID.String(), "Client", createdAt)
	if err != nil {
		t.Fatal(err)
	}
	assessment.Status, assessment.BusinessAssetID = status, assetID
	assessment.Audit.CreatedAt, assessment.Audit.UpdatedAt = createdAt, updatedAt
	assessment.Audit.CreatedBy, assessment.Audit.UpdatedBy = createdBy, updatedBy
	if err := repository.Create(ctx, assessment); err != nil {
		t.Fatal(err)
	}
	return assessment
}
