package assessmentcycle_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	closuredom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentclosure"
	cmpdom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type closureDecisionReader struct{}

func (closureDecisionReader) ListAssessmentClosureReferences(context.Context, shared.ID, ports.AssessmentClosureReferenceQuery) ([]closuredom.Reference, error) {
	return nil, nil
}

func (closureDecisionReader) ResolveAssessmentClosureReference(context.Context, shared.ID, ports.AssessmentClosureReferenceQuery, closuredom.Reference) error {
	return nil
}

func TestClosurePreviewCommitReplayReopenAndStaleSafety(t *testing.T) {
	harness := newClosureHarness(t)
	ctx := context.Background()

	missingReason, err := harness.api.PreviewClosure(ctx, cycleuc.ClosurePreviewInput{TenantID: harness.tenantID, Actor: "reviewer", CycleID: harness.cycleID})
	if err != nil || missingReason.PreviewToken != "" || missingReason.Policy.CommitAllowed || !closureHasBlocker(missingReason.Policy.Blockers, cycleuc.CodeClosureReasonRequired) {
		t.Fatalf("missing reason preview=%+v err=%v", missingReason, err)
	}
	preview, err := harness.api.PreviewClosure(ctx, cycleuc.ClosurePreviewInput{TenantID: harness.tenantID, Actor: "reviewer", CycleID: harness.cycleID, Reason: "release accepted"})
	if err != nil || !preview.Policy.CommitAllowed || preview.PreviewToken == "" || len(preview.Path) != 2 || preview.Path[0].SnapshotID.IsZero() || preview.Path[1].SnapshotID.IsZero() {
		t.Fatalf("closure preview=%+v err=%v", preview, err)
	}
	wrongActor := cycleuc.ClosureCommitInput{
		Request: cycleuc.RetainedRequest{TenantID: harness.tenantID, Actor: "other", Route: "/closure-commits", IdempotencyKey: "close-wrong-actor"},
		CycleID: harness.cycleID, ExpectedVersion: preview.CycleVersion, PreviewToken: preview.PreviewToken, Reason: "release accepted",
	}
	if _, err := harness.api.CommitClosure(ctx, wrongActor); !errors.Is(err, shared.ErrConflict) || cycleuc.ErrorCode(err) != cycleuc.CodeClosurePreviewStale {
		t.Fatalf("actor mismatch error=%v code=%s", err, cycleuc.ErrorCode(err))
	}
	commit := cycleuc.ClosureCommitInput{
		Request: cycleuc.RetainedRequest{TenantID: harness.tenantID, Actor: "reviewer", Route: "/closure-commits", IdempotencyKey: "close-1"},
		CycleID: harness.cycleID, ExpectedVersion: preview.CycleVersion, PreviewToken: preview.PreviewToken, Reason: "release accepted",
	}
	response, err := harness.api.CommitClosure(ctx, commit)
	if err != nil || response.StatusCode != 201 || response.Replayed {
		t.Fatalf("closure commit=%+v err=%v", response, err)
	}
	var committed cycleuc.ClosureCommitResult
	if err := json.Unmarshal(response.Body, &committed); err != nil {
		t.Fatal(err)
	}
	if committed.Manifest.ContentHash == "" || committed.Cycle.Status != cycledom.StatusCompleted || committed.Cycle.ActiveClosureManifestID != committed.Manifest.ID || committed.ReportJobID == "" {
		t.Fatalf("closure result=%+v", committed)
	}
	replay, err := harness.api.CommitClosure(ctx, commit)
	if err != nil || !replay.Replayed || string(replay.Body) != string(response.Body) {
		t.Fatalf("closure replay=%+v err=%v", replay, err)
	}
	commit.Request.IdempotencyKey = "close-reused-preview"
	if _, err := harness.api.CommitClosure(ctx, commit); !errors.Is(err, shared.ErrConflict) || cycleuc.ErrorCode(err) != cycleuc.CodeClosurePreviewStale {
		t.Fatalf("reused closure preview error=%v code=%s", err, cycleuc.ErrorCode(err))
	}
	job, err := harness.queue.Claim(ctx, time.Minute, "assessment_cycle_report")
	if err != nil || job == nil || job.Kind != "assessment_cycle_report" {
		t.Fatalf("report job=%+v err=%v", job, err)
	}

	reopenPreview, err := harness.api.PreviewReopen(ctx, cycleuc.ReopenPreviewInput{TenantID: harness.tenantID, Actor: "reviewer", CycleID: harness.cycleID})
	if err != nil || reopenPreview.PreviewToken == "" || reopenPreview.Manifest.ID != committed.Manifest.ID {
		t.Fatalf("reopen preview=%+v err=%v", reopenPreview, err)
	}
	reopen := cycleuc.ReopenCommitInput{
		Request: cycleuc.RetainedRequest{TenantID: harness.tenantID, Actor: "reviewer", Route: "/reopen-commits", IdempotencyKey: "reopen-1"},
		CycleID: harness.cycleID, ExpectedVersion: reopenPreview.CycleVersion, PreviewToken: reopenPreview.PreviewToken, Reason: "additional testing required",
	}
	reopenedResponse, err := harness.api.CommitReopen(ctx, reopen)
	if err != nil || reopenedResponse.StatusCode != 200 {
		t.Fatalf("reopen commit=%+v err=%v", reopenedResponse, err)
	}
	var reopened cycleuc.ReopenCommitResult
	if err := json.Unmarshal(reopenedResponse.Body, &reopened); err != nil {
		t.Fatal(err)
	}
	if reopened.Cycle.Status != cycledom.StatusOpen || reopened.Cycle.ActiveClosureManifestID != "" || reopened.SupersededManifest.Lifecycle != "superseded" {
		t.Fatalf("reopen result=%+v", reopened)
	}
	reopen.Request.IdempotencyKey = "reopen-reused-preview"
	if _, err := harness.api.CommitReopen(ctx, reopen); !errors.Is(err, shared.ErrConflict) || cycleuc.ErrorCode(err) != cycleuc.CodeReopenPreviewStale {
		t.Fatalf("reused reopen preview error=%v code=%s", err, cycleuc.ErrorCode(err))
	}
	history, err := harness.api.ListClosureManifests(ctx, harness.tenantID, harness.cycleID)
	if err != nil || len(history) != 1 || history[0].Lifecycle != "superseded" {
		t.Fatalf("closure history=%+v err=%v", history, err)
	}
	if _, err := harness.api.PreviewClosure(ctx, cycleuc.ClosurePreviewInput{TenantID: "other-tenant", Actor: "reviewer", CycleID: harness.cycleID, Reason: "cross tenant"}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant preview must not reveal cycle, got %v", err)
	}
}

func TestClosureCommitRejectsConcurrentCycleMutation(t *testing.T) {
	harness := newClosureHarness(t)
	ctx := context.Background()
	preview, err := harness.api.PreviewClosure(ctx, cycleuc.ClosurePreviewInput{TenantID: harness.tenantID, Actor: "reviewer", CycleID: harness.cycleID, Reason: "release accepted"})
	if err != nil {
		t.Fatal(err)
	}
	cycle, err := harness.cycles.GetCycle(ctx, harness.tenantID, harness.cycleID)
	if err != nil {
		t.Fatal(err)
	}
	expected := cycle.Version
	if err := cycle.SelectHead(cycle.RootAssessmentID, expected, "other-reviewer", harness.clock.t.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := harness.cycles.UpdateCycleCAS(ctx, cycle, expected); err != nil {
		t.Fatal(err)
	}
	_, err = harness.api.CommitClosure(ctx, cycleuc.ClosureCommitInput{
		Request: cycleuc.RetainedRequest{TenantID: harness.tenantID, Actor: "reviewer", Route: "/closure-commits", IdempotencyKey: "close-stale-version"},
		CycleID: harness.cycleID, ExpectedVersion: preview.CycleVersion, PreviewToken: preview.PreviewToken, Reason: "release accepted",
	})
	if !errors.Is(err, shared.ErrConflict) || cycleuc.ErrorCode(err) != cycleuc.CodeCycleVersionConflict {
		t.Fatalf("concurrent mutation error=%v code=%s", err, cycleuc.ErrorCode(err))
	}
}

type closureHarness struct {
	api         *cycleuc.APIService
	cycles      *memory.AssessmentCycleRepository
	snapshots   *memory.AssessmentSnapshotRepository
	comparisons *memory.AssessmentComparisonRepository
	queue       *memory.JobQueue
	clock       fixedClock
	tenantID    shared.ID
	cycleID     shared.ID
}

func newClosureHarness(t *testing.T) closureHarness {
	t.Helper()
	ctx := context.Background()
	tenantID := shared.ID("tenant-closure")
	clock := fixedClock{t: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	ids := &seqIDGen{}
	audit := &recordAudit{}
	engagements := memory.NewEngagementRepository()
	cycles := memory.NewAssessmentCycleRepository()
	snapshots := memory.NewAssessmentSnapshotRepository()
	comparisons := memory.NewAssessmentComparisonRepository()
	requests := memory.NewAssessmentCycleRequestRepository()
	transactions := memory.NewTenantTransactionRunner()
	queue := memory.NewJobQueue(ids, clock.Now)

	root := completedClosureEngagement(t, tenantID, "root", clock.t)
	final := completedClosureEngagement(t, tenantID, "final", clock.t)
	if err := engagements.Create(ctx, root); err != nil {
		t.Fatal(err)
	}
	if err := engagements.Create(ctx, final); err != nil {
		t.Fatal(err)
	}
	cycle, err := cycledom.NewAssessmentCycle("cycle-closure", tenantID, "Closure cycle", cycledom.BoundaryStandalone, "", "", root.ID, "owner", clock.t)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cycle.AdvanceRetest(final.ID, root.ID, cycle.Version, "owner", clock.t); err != nil {
		t.Fatal(err)
	}
	rootMember, _ := cycledom.NewInitialMember(tenantID, cycle.ID, root.ID, "owner", clock.t)
	finalMember, _ := cycledom.NewRetestMember(tenantID, cycle.ID, final.ID, root.ID, 1, "owner", clock.t)
	if err := cycles.CreateCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	if err := cycles.CreateMember(ctx, rootMember); err != nil {
		t.Fatal(err)
	}
	if err := cycles.CreateMember(ctx, finalMember); err != nil {
		t.Fatal(err)
	}
	rootSnapshot := closureSnapshot(t, tenantID, cycle.ID, root.ID, "snapshot-root", "run-root", clock.t)
	finalSnapshot := closureSnapshot(t, tenantID, cycle.ID, final.ID, "snapshot-final", "run-final", clock.t)
	if _, _, err := snapshots.CreateFinalizedCAS(ctx, rootSnapshot, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := snapshots.CreateFinalizedCAS(ctx, finalSnapshot, 0); err != nil {
		t.Fatal(err)
	}
	comparison := closureComparison(t, tenantID, cycle.ID, rootSnapshot, finalSnapshot, clock.t)
	queued, created, err := comparisons.CreateQueued(ctx, comparison)
	if err != nil || !created {
		t.Fatalf("create comparison=%+v created=%v err=%v", queued, created, err)
	}
	if err := comparison.Start(comparison.Version, clock.t); err != nil {
		t.Fatal(err)
	}
	if err := comparisons.UpdateCAS(ctx, comparison, 1); err != nil {
		t.Fatal(err)
	}
	if err := comparison.Complete(nil, comparison.Version, clock.t); err != nil {
		t.Fatal(err)
	}
	if err := comparisons.UpdateCAS(ctx, comparison, 2); err != nil {
		t.Fatal(err)
	}
	engagementService := enguc.NewService(engagements, clock, ids, audit)
	cycleService, err := cycleuc.NewService(cycles, engagements, nil, nil, transactions, ids, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	api, err := cycleuc.NewAPIService(cycleService, cycles, requests, engagementService, transactions, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	if err := api.SetClosureDependencies(cycles, snapshots, comparisons, closureDecisionReader{}, queue, []byte("0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	return closureHarness{api: api, cycles: cycles, snapshots: snapshots, comparisons: comparisons, queue: queue, clock: clock, tenantID: tenantID, cycleID: cycle.ID}
}

func completedClosureEngagement(t *testing.T, tenantID, id shared.ID, now time.Time) *engdom.Engagement {
	t.Helper()
	engagement, err := engdom.New(id, tenantID, id.String(), "client", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := engagement.Transition(engdom.StatusActive, now); err != nil {
		t.Fatal(err)
	}
	if err := engagement.Transition(engdom.StatusCompleted, now); err != nil {
		t.Fatal(err)
	}
	return engagement
}

func closureSnapshot(t *testing.T, tenantID, cycleID, assessmentID, snapshotID shared.ID, runID string, now time.Time) *assessmentsnapshot.Snapshot {
	t.Helper()
	finished := now.Add(-time.Minute)
	target, err := scanrun.CanonicalizeRepositoryTarget("https://example.com/repo.git", "0123456789abcdef0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	lane := scanrun.Lane{
		TenantID: tenantID, EngagementID: assessmentID, ScanRunID: runID, LaneKey: runID + "-lane", Producer: "sca", TerminalStatus: scanrun.StatusSucceeded,
		Target:                    target,
		AuthoritativeFindingKinds: []string{"vulnerability"}, IncludedScope: []string{"src/**"}, ExcludedScope: []string{"vendor/**"},
		StartedAt: finished.Add(-time.Minute), FinishedAt: &finished, ResultRef: "result:" + runID, EvidenceRef: "evidence:" + runID,
		ResultSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ManifestSchemaVersion: scanrun.CurrentManifestSchemaVersion, SealedAt: &finished,
		Versions: []scanrun.LaneVersion{{VersionKind: scanrun.VersionScanner, Name: "sca", Version: "1"}}, Stages: []scanrun.LaneStage{{StageKey: "scan", Status: scanrun.StageSucceeded, StartedAt: finished.Add(-time.Minute), FinishedAt: &finished}},
	}
	lane.ManifestHash, err = scanrun.ComputeManifestHash(lane)
	if err != nil {
		t.Fatal(err)
	}
	lanes := []scanrun.Lane{lane}
	manifestHash, err := scanrun.ComputeRunManifestHash(lanes)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := assessmentsnapshot.NewFinalized(tenantID, snapshotID, cycleID, assessmentID, assessmentsnapshot.Boundary{Kind: cycledom.BoundaryStandalone}, "request-"+snapshotID.String(), "scanner", now, []assessmentsnapshot.SelectedRun{{
		ID: runID, ManifestHash: manifestHash, Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusSucceeded, Trusted: true, Lanes: lanes,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func closureComparison(t *testing.T, tenantID, cycleID shared.ID, initial, final *assessmentsnapshot.Snapshot, now time.Time) cmpdom.Comparison {
	t.Helper()
	input := cmpdom.GenerationInput{
		Mode: cmpdom.ModeLifecycle, Baseline: cmpdom.SnapshotHashRef{ID: initial.ID, ContentHash: initial.ContentHash}, Current: cmpdom.SnapshotHashRef{ID: final.ID, ContentHash: final.ContentHash},
		AlgorithmVersion: 1, FingerprintVersion: 1, RiskModelVersion: 1, CoveragePolicyVersion: 1,
	}
	payload, inputHash, err := cmpdom.HashGenerationInput(input)
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := cmpdom.NewQueued(tenantID, cycleID, "comparison", input, payload, inputHash, now)
	if err != nil {
		t.Fatal(err)
	}
	return comparison
}

func closureHasBlocker(blockers []closuredom.Blocker, code string) bool {
	for _, blocker := range blockers {
		if blocker.Code == code {
			return true
		}
	}
	return false
}
