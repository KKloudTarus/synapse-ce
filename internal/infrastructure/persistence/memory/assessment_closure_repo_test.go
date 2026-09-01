package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentclosure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestAssessmentClosureRepositoryCommitReopenAndHistory(t *testing.T) {
	ctx := context.Background()
	repository := NewAssessmentCycleRepository()
	now := time.Date(2026, 9, 1, 4, 0, 0, 0, time.UTC)
	cycle, err := assessmentcycle.NewAssessmentCycle("cycle", "tenant", "Cycle", assessmentcycle.BoundaryStandalone, "", "", "root", "owner", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cycle.AdvanceRetest("final", "root", cycle.Version, "owner", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := repository.CreateCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	root, _ := assessmentcycle.NewInitialMember("tenant", "cycle", "root", "owner", now)
	final, _ := assessmentcycle.NewRetestMember("tenant", "cycle", "final", "root", 1, "owner", now.Add(time.Minute))
	if err := repository.CreateMember(ctx, root); err != nil {
		t.Fatal(err)
	}
	if err := repository.CreateMember(ctx, final); err != nil {
		t.Fatal(err)
	}
	manifest := memoryClosureManifest(t, cycle, now.Add(2*time.Minute))
	expectedVersion := cycle.Version
	if err := cycle.CompleteWithManifest(manifest.ID, expectedVersion, "reviewer", now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := manifest.Seal(now.Add(3*time.Minute), "reviewer"); err != nil {
		t.Fatal(err)
	}
	if err := repository.CommitClosure(ctx, ports.AssessmentClosureCommit{Manifest: manifest, Cycle: cycle, ExpectedCycleVersion: expectedVersion}); err != nil {
		t.Fatalf("commit closure: %v", err)
	}
	active, err := repository.GetActiveClosureManifest(ctx, "tenant", "cycle")
	if err != nil || active.ID != manifest.ID || active.Lifecycle != assessmentclosure.LifecycleActive {
		t.Fatalf("active manifest=%+v err=%v", active, err)
	}
	if err := active.Validate(); err != nil {
		t.Fatalf("read-back active manifest: %v", err)
	}
	if err := repository.CommitClosure(ctx, ports.AssessmentClosureCommit{Manifest: manifest, Cycle: cycle, ExpectedCycleVersion: expectedVersion}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("replayed stale commit should conflict, got %v", err)
	}

	reopenedCycle, err := repository.GetCycle(ctx, "tenant", "cycle")
	if err != nil {
		t.Fatal(err)
	}
	reopenExpected := reopenedCycle.Version
	if err := reopenedCycle.ReopenFromManifest(reopenExpected, "reviewer", now.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := active.Supersede(now.Add(4*time.Minute), ""); err != nil {
		t.Fatal(err)
	}
	if err := repository.ReopenClosure(ctx, ports.AssessmentClosureReopen{Manifest: active, Cycle: reopenedCycle, ExpectedCycleVersion: reopenExpected}); err != nil {
		t.Fatalf("reopen closure: %v", err)
	}
	if _, err := repository.GetActiveClosureManifest(ctx, "tenant", "cycle"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("reopened cycle must have no active manifest, got %v", err)
	}
	history, err := repository.ListClosureManifests(ctx, "tenant", "cycle")
	if err != nil || len(history) != 1 || history[0].Lifecycle != assessmentclosure.LifecycleSuperseded {
		t.Fatalf("history=%+v err=%v", history, err)
	}
}

func memoryClosureManifest(t *testing.T, cycle *assessmentcycle.AssessmentCycle, at time.Time) *assessmentclosure.Manifest {
	t.Helper()
	manifest, err := assessmentclosure.NewManifest("manifest", memoryManifestInput(cycle, at, 1))
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func memoryManifestInput(cycle *assessmentcycle.AssessmentCycle, at time.Time, version int64) assessmentclosure.ManifestInput {
	const initialHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const finalHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const comparisonHash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	initial := &assessmentsnapshot.Snapshot{TenantID: cycle.TenantID, CycleID: cycle.ID, ID: "snapshot-root", AssessmentID: cycle.RootAssessmentID, Lifecycle: assessmentsnapshot.LifecycleFinalized, ContentHash: initialHash}
	final := &assessmentsnapshot.Snapshot{TenantID: cycle.TenantID, CycleID: cycle.ID, ID: "snapshot-final", AssessmentID: cycle.SelectedHeadAssessmentID, Lifecycle: assessmentsnapshot.LifecycleFinalized, ContentHash: finalHash}
	comparison := &assessmentcomparison.Comparison{
		TenantID: cycle.TenantID, CycleID: cycle.ID, ID: "comparison", BaselineSnapshotID: initial.ID, CurrentSnapshotID: final.ID,
		Mode: assessmentcomparison.ModeLifecycle, Status: assessmentcomparison.StatusComplete, ContentHash: comparisonHash,
		AlgorithmVersion: 1, FingerprintVersion: 1, RiskModelVersion: 1,
	}
	return assessmentclosure.ManifestInput{
		TenantID: cycle.TenantID, CycleID: cycle.ID, ManifestVersion: version, CycleVersion: cycle.Version + 1,
		RootAssessmentID: cycle.RootAssessmentID, FinalAssessmentID: cycle.SelectedHeadAssessmentID,
		InitialSnapshot: initial, FinalSnapshot: final, Comparison: comparison,
		Path: []assessmentclosure.PathMember{
			{PathPosition: 0, AssessmentID: cycle.RootAssessmentID, AssessmentType: assessmentcycle.AssessmentTypeInitial, RelationshipVersion: 1, SnapshotID: initial.ID},
			{PathPosition: 1, AssessmentID: cycle.SelectedHeadAssessmentID, AssessmentType: assessmentcycle.AssessmentTypeRetest, RetestNumber: 1, RelationshipVersion: 1, SnapshotID: final.ID},
		},
		Reason: "complete", AsOfAt: at, CreatedAt: at, CreatedBy: "reviewer",
	}
}
