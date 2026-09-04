package assessmentsnapshot_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

type sequenceIDs struct{ next int }

func (ids *sequenceIDs) NewID() shared.ID {
	ids.next++
	return shared.ID(fmt.Sprintf("snapshot-%d", ids.next))
}

type auditRecorder struct{ entries []ports.AuditEntry }

func (audit *auditRecorder) Record(_ context.Context, entry ports.AuditEntry) error {
	audit.entries = append(audit.entries, entry)
	return nil
}

func TestFinalizeReplayReplacementAndCAS(t *testing.T) {
	harness := newHarness(t)
	first, created, err := harness.service.Finalize(context.Background(), uc.FinalizeInput{
		TenantID: "tenant", CycleID: "cycle", AssessmentID: "assessment", SelectedRunIDs: []string{"run-1"},
		RequestKey: "request-1", ExpectedDefaultVersion: 0, Actor: "operator",
	})
	if err != nil || !created || first.SnapshotNumber != 1 || first.Lifecycle != assessmentsnapshot.LifecycleFinalized {
		t.Fatalf("first finalize=%+v created=%v err=%v", first, created, err)
	}
	replay, created, err := harness.service.Finalize(context.Background(), uc.FinalizeInput{
		TenantID: "tenant", CycleID: "cycle", AssessmentID: "assessment", SelectedRunIDs: []string{"run-1"},
		RequestKey: "request-1", ExpectedDefaultVersion: 0, Actor: "operator",
	})
	if err != nil || created || replay.ID != first.ID {
		t.Fatalf("replay=%+v created=%v err=%v", replay, created, err)
	}

	harness.saveRun(t, nativeRun(t, "run-2", "assessment", "0123456789abcdef0123456789abcdef01234568"))
	second, created, err := harness.service.Finalize(context.Background(), uc.FinalizeInput{
		TenantID: "tenant", CycleID: "cycle", AssessmentID: "assessment", SelectedRunIDs: []string{"run-2"},
		RequestKey: "request-2", ExpectedDefaultVersion: 1, Actor: "operator",
	})
	if err != nil || !created || second.SnapshotNumber != 2 {
		t.Fatalf("second finalize=%+v created=%v err=%v", second, created, err)
	}
	old, err := harness.snapshots.Get(context.Background(), "tenant", first.ID)
	if err != nil || old.Lifecycle != assessmentsnapshot.LifecycleSuperseded {
		t.Fatalf("old snapshot=%+v err=%v", old, err)
	}
	if _, _, err := harness.service.Finalize(context.Background(), uc.FinalizeInput{
		TenantID: "tenant", CycleID: "cycle", AssessmentID: "assessment", SelectedRunIDs: []string{"run-1"},
		RequestKey: "request-stale", ExpectedDefaultVersion: 1, Actor: "operator",
	}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale CAS error=%v", err)
	}
	if len(harness.audit.entries) != 2 {
		t.Fatalf("audit entries=%d, want 2", len(harness.audit.entries))
	}
	for _, entry := range harness.audit.entries {
		for key, value := range entry.Metadata {
			joined := key + "=" + value
			if strings.Contains(joined, "request-") || strings.Contains(joined, "result:") || strings.Contains(joined, "evidence:") {
				t.Fatalf("snapshot audit leaked request/evidence material: %s", joined)
			}
		}
	}
}

func TestFinalizeRejectsTerminalAssessmentAndBuildingRun(t *testing.T) {
	harness := newHarness(t)
	assessment, err := harness.engagements.GetByIDInTenant(context.Background(), "tenant", "assessment")
	if err != nil {
		t.Fatal(err)
	}
	if err := assessment.Transition(engagement.StatusCompleted, harness.clock.now); err != nil {
		t.Fatal(err)
	}
	if err := harness.engagements.Update(context.Background(), assessment); err != nil {
		t.Fatal(err)
	}
	if _, _, err := harness.service.Finalize(context.Background(), uc.FinalizeInput{
		TenantID: "tenant", CycleID: "cycle", AssessmentID: "assessment", SelectedRunIDs: []string{"run-1"},
		RequestKey: "completed", Actor: "operator",
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("completed assessment error=%v", err)
	}

	other := newHarness(t)
	building := scanrun.ScanRun{TenantID: "tenant", ID: "building", EngagementID: "assessment", CreatedAt: other.clock.now, UpdatedAt: other.clock.now, Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusBuilding, ManifestSchemaVersion: scanrun.CurrentManifestSchemaVersion}
	if err := other.runs.SaveScanRun(context.Background(), building); err != nil {
		t.Fatal(err)
	}
	if _, _, err := other.service.Finalize(context.Background(), uc.FinalizeInput{
		TenantID: "tenant", CycleID: "cycle", AssessmentID: "assessment", SelectedRunIDs: []string{"building"},
		RequestKey: "building", Actor: "operator",
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("building run error=%v", err)
	}
}

func TestFinalizeDerivesCycleAndScopesIdempotencyToSelectedLanes(t *testing.T) {
	harness := newHarness(t)
	finalized, created, err := harness.service.Finalize(context.Background(), uc.FinalizeInput{
		TenantID: "tenant", AssessmentID: "assessment",
		SelectedRuns: []uc.RunSelection{{RunID: "run-1", LaneKeys: []string{"sca"}}},
		RequestKey:   "derived-cycle", ExpectedDefaultVersion: 0, Actor: "operator",
	})
	if err != nil || !created || finalized.CycleID != "cycle" || len(finalized.RunReferences) != 1 || len(finalized.RunReferences[0].LaneReferences) != 1 {
		t.Fatalf("derived cycle finalize=%+v created=%v err=%v", finalized, created, err)
	}
	if _, _, err := harness.service.Finalize(context.Background(), uc.FinalizeInput{
		TenantID: "tenant", AssessmentID: "assessment",
		SelectedRuns: []uc.RunSelection{{RunID: "run-1", LaneKeys: []string{"other"}}},
		RequestKey:   "derived-cycle", ExpectedDefaultVersion: 0, Actor: "operator",
	}); !errors.Is(err, uc.ErrIdempotencyBodyMismatch) || !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("selected-lane idempotency mismatch=%v", err)
	}
}

type harness struct {
	service     *uc.Service
	snapshots   *memory.AssessmentSnapshotRepository
	engagements *memory.EngagementRepository
	runs        *memory.ScanRunStore
	audit       *auditRecorder
	clock       fixedClock
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	clock := fixedClock{now: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)}
	engagements := memory.NewEngagementRepository()
	assessment, err := engagement.New("assessment", "tenant", "Assessment", "", clock.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := assessment.Transition(engagement.StatusActive, clock.now); err != nil {
		t.Fatal(err)
	}
	if err := engagements.Create(context.Background(), assessment); err != nil {
		t.Fatal(err)
	}
	cycles := memory.NewAssessmentCycleRepository()
	cycle, err := assessmentcycle.NewAssessmentCycle("cycle", "tenant", "Cycle", assessmentcycle.BoundaryStandalone, "", "", "assessment", "operator", clock.now)
	if err != nil {
		t.Fatal(err)
	}
	member, err := assessmentcycle.NewInitialMember("tenant", "cycle", "assessment", "operator", clock.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := cycles.CreateCycle(context.Background(), cycle); err != nil {
		t.Fatal(err)
	}
	if err := cycles.CreateMember(context.Background(), member); err != nil {
		t.Fatal(err)
	}
	runs := memory.NewScanRunStore()
	snapshots := memory.NewAssessmentSnapshotRepository()
	audit := &auditRecorder{}
	service, err := uc.NewService(snapshots, cycles, engagements, runs, memory.NewTenantTransactionRunner(), &sequenceIDs{}, clock, audit)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{service: service, snapshots: snapshots, engagements: engagements, runs: runs, audit: audit, clock: clock}
	h.saveRun(t, nativeRun(t, "run-1", "assessment", "0123456789abcdef0123456789abcdef01234567"))
	return h
}

func (h *harness) saveRun(t *testing.T, run scanrun.ScanRun) {
	t.Helper()
	if err := h.runs.SaveScanRun(context.Background(), run); err != nil {
		t.Fatal(err)
	}
}

func nativeRun(t *testing.T, id, assessmentID, revision string) scanrun.ScanRun {
	t.Helper()
	started := time.Date(2026, 8, 31, 11, 0, 0, 0, time.UTC)
	finished := started.Add(time.Minute)
	target, err := scanrun.CanonicalizeRepositoryTarget("https://example.com/repo.git", revision)
	if err != nil {
		t.Fatal(err)
	}
	run := scanrun.ScanRun{
		TenantID: "tenant", ID: id, EngagementID: shared.ID(assessmentID), CreatedAt: started, UpdatedAt: started,
		Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusBuilding,
		ManifestSchemaVersion: scanrun.CurrentManifestSchemaVersion,
		Lanes: []scanrun.Lane{{
			TenantID: "tenant", EngagementID: shared.ID(assessmentID), ScanRunID: id,
			LaneKey: "sca", Producer: "sca", TerminalStatus: scanrun.StatusSucceeded, Target: target,
			AuthoritativeFindingKinds: []string{"vulnerability"}, IncludedScope: []string{"src/**"}, ExcludedScope: []string{"vendor/**"},
			StartedAt: started, FinishedAt: &finished, ResultRef: "result:" + id, EvidenceRef: "evidence:" + id,
			ResultSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ManifestSchemaVersion: 1,
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
