package assessmentlifecycle

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	comparisonuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcomparison"
	snapshotuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type shadowClock struct{ now time.Time }

func (clock *shadowClock) Now() time.Time {
	clock.now = clock.now.Add(time.Second)
	return clock.now
}

type shadowIDs struct{ next int }

func (ids *shadowIDs) NewID() shared.ID {
	ids.next++
	return shared.ID(fmt.Sprintf("shadow-%d", ids.next))
}

type shadowAudit struct{}

func (shadowAudit) Record(context.Context, ports.AuditEntry) error { return nil }

type shadowVerificationReader struct{}

func (shadowVerificationReader) ListEffectiveComparisonVerifications(context.Context, shared.ID, shared.ID, []shared.ID) ([]ports.AssessmentComparisonVerification, error) {
	return nil, nil
}

func TestShadowCoordinatorContinuouslyProjectsScanRuns(t *testing.T) {
	ctx := context.Background()
	tenantID, cycleID, assessmentID := shared.ID("tenant"), shared.ID("cycle"), shared.ID("assessment")
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	clock, ids := &shadowClock{now: now}, &shadowIDs{}

	engagements := memory.NewEngagementRepository()
	assessment, err := engagement.New(assessmentID, tenantID, "Assessment", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := assessment.Transition(engagement.StatusActive, now); err != nil {
		t.Fatal(err)
	}
	if err := engagements.Create(ctx, assessment); err != nil {
		t.Fatal(err)
	}

	cycles := memory.NewAssessmentCycleRepository()
	cycle, err := assessmentcycle.NewAssessmentCycle(cycleID, tenantID, "Cycle", assessmentcycle.BoundaryStandalone, "", "", assessmentID, "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	member, err := assessmentcycle.NewInitialMember(tenantID, cycleID, assessmentID, "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := cycles.CreateCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	if err := cycles.CreateMember(ctx, member); err != nil {
		t.Fatal(err)
	}

	runs := memory.NewScanRunStore()
	saveShadowRun(t, runs, shadowRun(t, tenantID, assessmentID, "run-1", "0123456789abcdef0123456789abcdef01234567"))
	saveShadowRun(t, runs, shadowRun(t, tenantID, assessmentID, "run-2", "1123456789abcdef0123456789abcdef01234567"))
	snapshots := memory.NewAssessmentSnapshotRepository()
	transactions := memory.NewTenantTransactionRunner()
	finalizer, err := snapshotuc.NewService(snapshots, cycles, engagements, runs, transactions, ids, clock, shadowAudit{})
	if err != nil {
		t.Fatal(err)
	}
	comparisons := memory.NewAssessmentComparisonRepository()
	comparisonService, err := comparisonuc.NewService(comparisons, snapshots, cycles, memory.NewFindingLineageRepository(), transactions, shadowAudit{}, clock, ids, shadowVerificationReader{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	enabled := false
	coordinator, err := NewShadowCoordinator(cycles, snapshots, finalizer, comparisonService, func(string) bool { return enabled })
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.AssessmentScanRunSealed(ctx, tenantID, assessmentID, "run-1"); err != nil {
		t.Fatal(err)
	}
	if items, err := snapshots.ListByAssessment(ctx, tenantID, assessmentID); err != nil || len(items) != 0 {
		t.Fatalf("disabled snapshots=%d err=%v", len(items), err)
	}

	enabled = true
	if err := coordinator.AssessmentScanRunSealed(ctx, tenantID, assessmentID, "run-1"); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.AssessmentScanRunSealed(ctx, tenantID, assessmentID, "run-2"); err != nil {
		t.Fatal(err)
	}
	items, err := snapshots.ListByAssessment(ctx, tenantID, assessmentID)
	if err != nil || len(items) != 2 {
		t.Fatalf("snapshots=%d err=%v", len(items), err)
	}
	queued, err := comparisons.ListMetadataByCycle(ctx, tenantID, cycleID)
	if err != nil || len(queued) != 1 {
		t.Fatalf("comparisons=%d err=%v", len(queued), err)
	}
	if queued[0].Mode != assessmentcomparison.ModeLifecycle || queued[0].BaselineSnapshotID != items[0].ID || queued[0].CurrentSnapshotID != items[1].ID {
		t.Fatalf("unexpected lifecycle comparison: %+v snapshots=%+v", queued[0], items)
	}

	if err := coordinator.AssessmentScanRunSealed(ctx, tenantID, assessmentID, "run-2"); err != nil {
		t.Fatal(err)
	}
	items, _ = snapshots.ListByAssessment(ctx, tenantID, assessmentID)
	queued, _ = comparisons.ListMetadataByCycle(ctx, tenantID, cycleID)
	if len(items) != 2 || len(queued) != 1 {
		t.Fatalf("replay created duplicate artifacts: snapshots=%d comparisons=%d", len(items), len(queued))
	}
}

func saveShadowRun(t *testing.T, store *memory.ScanRunStore, run scanrun.ScanRun) {
	t.Helper()
	if err := store.SaveScanRun(context.Background(), run); err != nil {
		t.Fatal(err)
	}
}

func shadowRun(t *testing.T, tenantID, assessmentID shared.ID, id, revision string) scanrun.ScanRun {
	t.Helper()
	started := time.Date(2026, 9, 4, 11, 0, 0, 0, time.UTC)
	finished := started.Add(time.Minute)
	target, err := scanrun.CanonicalizeRepositoryTarget("https://example.com/repo.git", revision)
	if err != nil {
		t.Fatal(err)
	}
	run := scanrun.ScanRun{
		TenantID: tenantID, ID: id, EngagementID: assessmentID, CreatedAt: started, UpdatedAt: started,
		Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusBuilding,
		ManifestSchemaVersion: scanrun.CurrentManifestSchemaVersion,
		Lanes: []scanrun.Lane{{
			TenantID: tenantID, EngagementID: assessmentID, ScanRunID: id, LaneKey: "sca", Producer: "sca", TerminalStatus: scanrun.StatusSucceeded, Target: target,
			AuthoritativeFindingKinds: []string{"vulnerability"}, IncludedScope: []string{"src/**"}, ExcludedScope: []string{"vendor/**"},
			StartedAt: started, FinishedAt: &finished, ResultRef: "result:" + id, EvidenceRef: "evidence:" + id,
			ResultSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ManifestSchemaVersion: scanrun.CurrentManifestSchemaVersion,
			Versions: []scanrun.LaneVersion{{VersionKind: scanrun.VersionScanner, Name: "sca", Version: "1"}, {VersionKind: scanrun.VersionRulePack, Name: "rules", Version: "1"}},
			Stages:   []scanrun.LaneStage{{StageKey: "scan", Status: scanrun.StageSucceeded, StartedAt: started, FinishedAt: &finished}},
		}},
	}
	run.Lanes[0].SealedAt = &finished
	run.Lanes[0].ManifestHash, err = scanrun.ComputeManifestHash(run.Lanes[0])
	if err != nil {
		t.Fatal(err)
	}
	run.ManifestHash, err = scanrun.ComputeRunManifestHash(run.Lanes)
	if err != nil {
		t.Fatal(err)
	}
	run.TerminalStatus, run.SealedAt, run.UpdatedAt = scanrun.StatusSucceeded, &finished, finished
	return run
}
