package assessmentsnapshot_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	uc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type snapshotBackfillClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *snapshotBackfillClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *snapshotBackfillClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

type staticBackfillRunStore struct{ runs []scanrun.ScanRun }

func (store *staticBackfillRunStore) ListScanRuns(_ context.Context, tenantID, assessmentID shared.ID) ([]scanrun.ScanRun, error) {
	var out []scanrun.ScanRun
	for _, run := range store.runs {
		if run.TenantID == tenantID && run.EngagementID == assessmentID {
			out = append(out, run)
		}
	}
	return out, nil
}
func (store *staticBackfillRunStore) GetScanRun(_ context.Context, tenantID shared.ID, runID string) (scanrun.ScanRun, error) {
	for _, run := range store.runs {
		if run.TenantID == tenantID && run.ID == runID {
			return run, nil
		}
	}
	return scanrun.ScanRun{}, shared.ErrNotFound
}

type retryingSnapshotProjector struct {
	calls int
	err   error
}

type cancellingSnapshotSource struct{ cancel context.CancelFunc }

func (source cancellingSnapshotSource) ListAssessmentSnapshotBackfillEngagements(context.Context, shared.ID, shared.ID, time.Time, int) ([]*engagement.Engagement, error) {
	source.cancel()
	return nil, context.Canceled
}

func (projector *retryingSnapshotProjector) Project(context.Context, uc.LegacyProjectionInput) (uc.LegacyProjectionResult, error) {
	projector.calls++
	return uc.LegacyProjectionResult{}, projector.err
}

func TestSnapshotBackfillProjectsUnknownCoverageAndHashVersionedEvidence(t *testing.T) {
	harness := newSnapshotBackfillHarness(t, nil)
	run := nativeRun(t, "sealed-run", "assessment", "0123456789abcdef0123456789abcdef01234567")
	harness.runs.runs = []scanrun.ScanRun{run}
	if err := harness.results.SaveResult(context.Background(), "assessment", []byte(`{"findings":[{"id":"source-only"}]}`)); err != nil {
		t.Fatal(err)
	}

	first, err := harness.runner.Run(context.Background(), uc.BackfillRequest{TenantID: "tenant", Actor: "operator", LeaseOwner: "process-1", BatchSize: 1})
	if err != nil || first.CreatedCount != 1 || first.FailedCount != 0 {
		t.Fatalf("first snapshot backfill=%+v err=%v", first, err)
	}
	snapshots, err := harness.snapshots.ListByAssessment(context.Background(), "tenant", "assessment")
	if err != nil || len(snapshots) != 1 {
		t.Fatalf("snapshots=%+v err=%v", snapshots, err)
	}
	if snapshots[0].Provenance != assessmentsnapshot.ProvenanceLegacy || len(snapshots[0].Dimensions) != 1 || snapshots[0].Dimensions[0].State != assessmentsnapshot.CoverageUnknown || snapshots[0].Dimensions[0].ReasonCode != assessmentsnapshot.ReasonLegacyProvenance {
		t.Fatalf("legacy projection coverage=%+v", snapshots[0])
	}
	if _, _, err := harness.snapshots.GetDefault(context.Background(), "tenant", "assessment"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("legacy projection changed default pointer: %v", err)
	}

	second, err := harness.runner.Run(context.Background(), uc.BackfillRequest{TenantID: "tenant", Actor: "operator", LeaseOwner: "process-2", BatchSize: 1})
	if err != nil || second.SkippedCount != 1 || second.CreatedCount != 0 {
		t.Fatalf("idempotent rerun=%+v err=%v", second, err)
	}
	if err := harness.results.SaveResult(context.Background(), "assessment", []byte(`{"findings":[{"id":"changed-source"}]}`)); err != nil {
		t.Fatal(err)
	}
	third, err := harness.runner.Run(context.Background(), uc.BackfillRequest{TenantID: "tenant", Actor: "operator", LeaseOwner: "process-3", BatchSize: 1})
	if err != nil || third.CreatedCount != 1 {
		t.Fatalf("hash-versioned rerun=%+v err=%v", third, err)
	}
	snapshots, err = harness.snapshots.ListByAssessment(context.Background(), "tenant", "assessment")
	if err != nil || len(snapshots) != 2 || snapshots[0].ContentHash != snapshots[1].ContentHash || snapshots[0].RequestHash == snapshots[1].RequestHash {
		t.Fatalf("hash-versioned snapshots=%+v err=%v", snapshots, err)
	}
}

func TestSnapshotBackfillProjectsLegacyRunWithoutInventedDimensions(t *testing.T) {
	legacy := scanrun.ScanRun{
		TenantID: "tenant", ID: "legacy-run", EngagementID: "assessment",
		CreatedAt: time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC),
		Provenance: scanrun.ProvenanceLegacy, TerminalStatus: scanrun.StatusUnknown, ManifestSchemaVersion: scanrun.CurrentManifestSchemaVersion,
		LegacyFindingKeys: []string{"legacy-finding"},
	}
	harness := newSnapshotBackfillHarness(t, []scanrun.ScanRun{legacy})
	run, err := harness.runner.Run(context.Background(), uc.BackfillRequest{TenantID: "tenant", Actor: "operator", LeaseOwner: "legacy", BatchSize: 1})
	if err != nil || run.CreatedCount != 1 {
		t.Fatalf("legacy no-lane backfill=%+v err=%v", run, err)
	}
	snapshots, err := harness.snapshots.ListByAssessment(context.Background(), "tenant", "assessment")
	if err != nil || len(snapshots) != 1 || len(snapshots[0].RunReferences) != 1 || len(snapshots[0].Dimensions) != 0 {
		t.Fatalf("legacy no-lane projection=%+v err=%v", snapshots, err)
	}
}

func TestSnapshotBackfillLeaseResumeDryRunAndRedactedRetry(t *testing.T) {
	harness := newSnapshotBackfillHarness(t, []scanrun.ScanRun{nativeRun(t, "sealed-run", "assessment", "0123456789abcdef0123456789abcdef01234567")})
	dryRun, err := harness.runner.Run(context.Background(), uc.BackfillRequest{TenantID: "tenant", Actor: "operator", LeaseOwner: "dry-run", DryRun: true, BatchSize: 1})
	if err != nil || dryRun.WouldCreateCount != 1 {
		t.Fatalf("dry run=%+v err=%v", dryRun, err)
	}
	if snapshots, _ := harness.snapshots.ListByAssessment(context.Background(), "tenant", "assessment"); len(snapshots) != 0 {
		t.Fatalf("dry run created snapshots: %+v", snapshots)
	}

	lease := time.Minute
	crashed, _, err := harness.store.AcquireAssessmentSnapshotBackfillRun(context.Background(), ports.AssessmentSnapshotBackfillAcquireRequest{Run: ports.AssessmentSnapshotBackfillRun{
		TenantID: "tenant", ID: "crashed", SchemaVersion: uc.AssessmentSnapshotBackfillSchemaVersion, BatchSize: 1,
		SnapshotAt: harness.clock.Now(), State: ports.AssessmentSnapshotBackfillRunning, LeaseOwner: "dead", LeaseToken: "dead-token", LeaseExpiresAt: harness.clock.Now().Add(lease),
		CreatedBy: "operator", CreatedAt: harness.clock.Now(), UpdatedAt: harness.clock.Now(),
	}, LeaseDuration: lease})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := harness.runner.Run(context.Background(), uc.BackfillRequest{TenantID: "tenant", Actor: "operator", LeaseOwner: "live", BatchSize: 1, LeaseDuration: lease}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("concurrent lease=%v", err)
	}
	harness.clock.Advance(lease + time.Second)
	resumed, err := harness.runner.Run(context.Background(), uc.BackfillRequest{TenantID: "tenant", Actor: "operator", LeaseOwner: "live", BatchSize: 1, LeaseDuration: lease})
	if err != nil || resumed.ID != crashed.ID || resumed.CreatedCount != 1 {
		t.Fatalf("crash resume=%+v err=%v", resumed, err)
	}

	retryHarness := newSnapshotBackfillHarness(t, []scanrun.ScanRun{nativeRun(t, "retry-run", "assessment", "0123456789abcdef0123456789abcdef01234567")})
	failing := &retryingSnapshotProjector{err: errors.New("database unavailable: secret-token")}
	retryHarness.runner, err = uc.NewBackfillRunner(failing, retryHarness.engagements, retryHarness.store, retryHarness.runs, retryHarness.results, retryHarness.ids, retryHarness.clock, retryHarness.audit, nil)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := retryHarness.runner.Run(context.Background(), uc.BackfillRequest{TenantID: "tenant", Actor: "operator", LeaseOwner: "retry", BatchSize: 1})
	if err != nil || failed.FailedCount != 1 || failing.calls != 3 {
		t.Fatalf("bounded retry=%+v calls=%d err=%v", failed, failing.calls, err)
	}
	item, err := retryHarness.store.GetAssessmentSnapshotBackfillItem(context.Background(), "tenant", failed.ID, "assessment")
	if err != nil || item.ReasonCode != uc.SnapshotBackfillReasonProjectionWriteFailed || !item.Retryable || strings.Contains(item.RepairGuidance, "secret-token") {
		t.Fatalf("redacted failure=%+v err=%v", item, err)
	}

	cancelHarness := newSnapshotBackfillHarness(t, []scanrun.ScanRun{nativeRun(t, "cancel-run", "assessment", "0123456789abcdef0123456789abcdef01234567")})
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancelRunner, err := uc.NewBackfillRunner(cancelHarness.projector, cancellingSnapshotSource{cancel: cancel}, cancelHarness.store, cancelHarness.runs, cancelHarness.results, cancelHarness.ids, cancelHarness.clock, cancelHarness.audit, nil)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, err := cancelRunner.Run(cancelCtx, uc.BackfillRequest{TenantID: "tenant", Actor: "operator", LeaseOwner: "cancel", BatchSize: 1})
	if !errors.Is(err, context.Canceled) || cancelled.State != ports.AssessmentSnapshotBackfillCancelled {
		t.Fatalf("cancelled run=%+v err=%v", cancelled, err)
	}
}

type snapshotBackfillHarness struct {
	runner      *uc.BackfillRunner
	snapshots   *memory.AssessmentSnapshotRepository
	engagements *memory.EngagementRepository
	store       *memory.AssessmentSnapshotBackfillRepository
	runs        *staticBackfillRunStore
	results     *memory.ScanResultStore
	ids         *sequenceIDs
	clock       *snapshotBackfillClock
	audit       *auditRecorder
	projector   *uc.LegacyProjector
}

func newSnapshotBackfillHarness(t *testing.T, runs []scanrun.ScanRun) *snapshotBackfillHarness {
	t.Helper()
	ctx := context.Background()
	clock := &snapshotBackfillClock{now: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	engagements := memory.NewEngagementRepository()
	assessment, err := engagement.New("assessment", "tenant", "Assessment", "", clock.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := assessment.Transition(engagement.StatusActive, clock.Now().Add(-23*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := engagements.Create(ctx, assessment); err != nil {
		t.Fatal(err)
	}
	cycles := memory.NewAssessmentCycleRepository()
	cycle, err := assessmentcycle.NewAssessmentCycle("cycle", "tenant", "Cycle", assessmentcycle.BoundaryStandalone, "", "", "assessment", "operator", assessment.Audit.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	member, err := assessmentcycle.NewInitialMember("tenant", "cycle", "assessment", "operator", assessment.Audit.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := cycles.CreateCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	if err := cycles.CreateMember(ctx, member); err != nil {
		t.Fatal(err)
	}
	snapshots := memory.NewAssessmentSnapshotRepository()
	store := memory.NewAssessmentSnapshotBackfillRepository()
	runStore := &staticBackfillRunStore{runs: runs}
	results := memory.NewScanResultStore()
	ids := &sequenceIDs{}
	audit := &auditRecorder{}
	projector, err := uc.NewLegacyProjector(snapshots, cycles, memory.NewTenantTransactionRunner(), ids, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := uc.NewBackfillRunner(projector, engagements, store, runStore, results, ids, clock, audit, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &snapshotBackfillHarness{runner: runner, snapshots: snapshots, engagements: engagements, store: store, runs: runStore, results: results, ids: ids, clock: clock, audit: audit, projector: projector}
}
