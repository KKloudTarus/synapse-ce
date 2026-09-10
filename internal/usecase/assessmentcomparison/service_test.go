package assessmentcomparison

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestServiceGeneratesReplaysAndSupersedesComparison(t *testing.T) {
	harness := newComparisonHarness(t)
	ctx := context.Background()
	queued, created, decision, err := harness.service.Queue(ctx, QueueInput{
		TenantID: harness.tenantID, BaselineSnapshotID: harness.snapshotsByNumber[2].ID, CurrentSnapshotID: harness.snapshotsByNumber[3].ID,
		Mode: assessmentcomparison.ModeLifecycle, FingerprintVersion: 1, RiskModelVersion: 1, Actor: "operator",
	})
	if err != nil || !created || !decision.Allowed {
		t.Fatalf("queue=%+v created=%v decision=%+v err=%v", queued, created, decision, err)
	}
	completed, err := harness.service.Generate(ctx, WorkInput{TenantID: harness.tenantID, ComparisonID: queued.ID, Actor: "worker", MaxAttempts: 3})
	if err != nil || completed.Status != assessmentcomparison.StatusNeedsReview {
		t.Fatalf("completed=%+v err=%v", completed, err)
	}
	if completed.Summary.FixedRate != (assessmentcomparison.Ratio{Numerator: 1, Denominator: 3}) || completed.Summary.ComparisonID != completed.ID || completed.Summary.RiskModelVersion != 1 {
		t.Fatalf("summary=%+v", completed.Summary)
	}
	assertPresence(t, completed, "fixed", assessmentcomparison.PresenceNotDetected)
	assertPresence(t, completed, "reopened", assessmentcomparison.PresenceReopened)
	assertPresence(t, completed, "still", assessmentcomparison.PresenceDetected)
	assertPresence(t, completed, "new", assessmentcomparison.PresenceNew)
	assertPresence(t, completed, "ambiguous", assessmentcomparison.PresenceNeedsReview)
	reopened := comparisonItem(t, completed, "reopened")
	if reopened.VerificationID != "verification-reopened" || reopened.VerificationState != "remediated" {
		t.Fatalf("reopened verification=%+v", reopened)
	}
	overridden := comparisonItem(t, completed, "override-target")
	if overridden.Presence != assessmentcomparison.PresenceDetected || overridden.CurrentObservationID != "observation-override-source-current" {
		t.Fatalf("overridden item=%+v", overridden)
	}
	for _, item := range completed.Items {
		if item.IdentityID == "override-source" {
			t.Fatalf("source identity leaked despite active override: %+v", item)
		}
	}

	replayed, err := harness.service.Generate(ctx, WorkInput{TenantID: harness.tenantID, ComparisonID: queued.ID, Actor: "worker", MaxAttempts: 3})
	if err != nil || replayed.ContentHash != completed.ContentHash || replayed.Version != completed.Version {
		t.Fatalf("generation replay=%+v err=%v", replayed, err)
	}
	requeued, created, _, err := harness.service.Queue(ctx, QueueInput{
		TenantID: harness.tenantID, BaselineSnapshotID: harness.snapshotsByNumber[2].ID, CurrentSnapshotID: harness.snapshotsByNumber[3].ID,
		Mode: assessmentcomparison.ModeLifecycle, FingerprintVersion: 1, RiskModelVersion: 1, Actor: "operator",
	})
	if err != nil || created || requeued.ID != completed.ID || requeued.ContentHash != completed.ContentHash {
		t.Fatalf("queue replay=%+v created=%v err=%v", requeued, created, err)
	}

	updatedCandidate, event, err := findinglineage.ResolveCandidate(harness.candidate, "candidate-resolution", findinglineage.ResolutionDismiss,
		"reviewer", "resolved ambiguity", nil, "", harness.candidate.Version, "", harness.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, applied, err := harness.lineage.ResolveCandidateCAS(ctx, updatedCandidate, event); err != nil || !applied {
		t.Fatalf("resolve candidate applied=%v err=%v", applied, err)
	}
	replacement, replaced, err := harness.service.Replace(ctx, ReplaceInput{TenantID: harness.tenantID, ComparisonID: completed.ID, Actor: "operator"})
	if err != nil || !replaced || replacement.ID == completed.ID || replacement.Status != assessmentcomparison.StatusQueued {
		t.Fatalf("replacement=%+v replaced=%v err=%v", replacement, replaced, err)
	}
	old, err := harness.comparisons.Get(ctx, harness.tenantID, completed.ID)
	if err != nil || old.Status != assessmentcomparison.StatusSuperseded || old.ContentHash != completed.ContentHash || len(old.Items) != len(completed.Items) {
		t.Fatalf("superseded old=%+v err=%v", old, err)
	}
	regenerated, err := harness.service.Generate(ctx, WorkInput{TenantID: harness.tenantID, ComparisonID: replacement.ID, Actor: "worker", MaxAttempts: 3})
	if err != nil || regenerated.Status != assessmentcomparison.StatusComplete {
		t.Fatalf("regenerated=%+v err=%v", regenerated, err)
	}
	assertPresence(t, regenerated, "ambiguous", assessmentcomparison.PresenceNew)
	replayedReplacement, replaced, err := harness.service.Replace(ctx, ReplaceInput{TenantID: harness.tenantID, ComparisonID: completed.ID, Actor: "operator"})
	if err != nil || replaced || replayedReplacement.ID != replacement.ID {
		t.Fatalf("replacement replay=%+v replaced=%v err=%v", replayedReplacement, replaced, err)
	}
	if len(harness.audit.entries) == 0 || len(harness.observer.entries) == 0 {
		t.Fatalf("missing audit or observer records: audit=%d observer=%d", len(harness.audit.entries), len(harness.observer.entries))
	}
}

func TestServiceRetriesDeadLettersAndRepairs(t *testing.T) {
	harness := newComparisonHarness(t)
	ctx := context.Background()
	queued, created, _, err := harness.service.Queue(ctx, QueueInput{
		TenantID: harness.tenantID, BaselineSnapshotID: harness.snapshotsByNumber[2].ID, CurrentSnapshotID: harness.snapshotsByNumber[3].ID,
		Mode: assessmentcomparison.ModeLifecycle, FingerprintVersion: 2, RiskModelVersion: 1, Actor: "operator",
	})
	if err != nil || !created {
		t.Fatalf("queue created=%v err=%v", created, err)
	}
	harness.verification.err = errors.New("verification backend unavailable")
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := harness.service.Generate(ctx, WorkInput{TenantID: harness.tenantID, ComparisonID: queued.ID, Actor: "worker", MaxAttempts: 2}); err == nil {
			t.Fatalf("attempt %d unexpectedly succeeded", attempt)
		}
		stored, getErr := harness.comparisons.Get(ctx, harness.tenantID, queued.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		want := assessmentcomparison.StatusQueued
		if attempt == 2 {
			want = assessmentcomparison.StatusFailed
		}
		if stored.Status != want || stored.Attempts != attempt {
			t.Fatalf("attempt=%d stored=%+v", attempt, stored)
		}
	}
	if _, err := harness.service.Generate(ctx, WorkInput{TenantID: harness.tenantID, ComparisonID: queued.ID, Actor: "worker", MaxAttempts: 2}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("dead-letter generate error=%v", err)
	}
	harness.verification.err = nil
	repaired, err := harness.service.Repair(ctx, WorkInput{TenantID: harness.tenantID, ComparisonID: queued.ID, Actor: "operator", MaxAttempts: 2})
	if err != nil || repaired.Status != assessmentcomparison.StatusNeedsReview || repaired.Attempts != 3 {
		t.Fatalf("repaired=%+v err=%v", repaired, err)
	}
}

func TestServiceRecoversGeneratingComparison(t *testing.T) {
	harness := newComparisonHarness(t)
	ctx := context.Background()
	queued, created, _, err := harness.service.Queue(ctx, QueueInput{
		TenantID: harness.tenantID, BaselineSnapshotID: harness.snapshotsByNumber[2].ID, CurrentSnapshotID: harness.snapshotsByNumber[3].ID,
		Mode: assessmentcomparison.ModeLifecycle, FingerprintVersion: 3, RiskModelVersion: 1, Actor: "operator",
	})
	if err != nil || !created {
		t.Fatalf("queue created=%v err=%v", created, err)
	}
	if err := queued.Start(queued.Version, harness.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if err := harness.comparisons.UpdateCAS(ctx, queued, queued.Version-1); err != nil {
		t.Fatal(err)
	}
	recovered, err := harness.service.Recover(ctx, WorkInput{TenantID: harness.tenantID, ComparisonID: queued.ID, Actor: "repair-worker", MaxAttempts: 2})
	if err != nil || recovered.Status != assessmentcomparison.StatusQueued || recovered.Attempts != 1 {
		t.Fatalf("recovered=%+v err=%v", recovered, err)
	}
	completed, err := harness.service.Generate(ctx, WorkInput{TenantID: harness.tenantID, ComparisonID: queued.ID, Actor: "worker", MaxAttempts: 2})
	if err != nil || completed.Status != assessmentcomparison.StatusNeedsReview || completed.Attempts != 2 {
		t.Fatalf("completed after recovery=%+v err=%v", completed, err)
	}
}

func TestServiceRejectsNeutralWhenLifecycleDirectionExists(t *testing.T) {
	harness := newComparisonHarness(t)
	comparison, created, decision, err := harness.service.Queue(context.Background(), QueueInput{
		TenantID: harness.tenantID, BaselineSnapshotID: harness.snapshotsByNumber[2].ID, CurrentSnapshotID: harness.snapshotsByNumber[3].ID,
		Mode: assessmentcomparison.ModeNeutral, FingerprintVersion: 1, RiskModelVersion: 1, Actor: "operator",
	})
	if err != nil || created || comparison.ID != "" || decision.Allowed || decision.ReasonCode != assessmentcomparison.ReasonLifecycleDirectionAvailable {
		t.Fatalf("comparison=%+v created=%v decision=%+v err=%v", comparison, created, decision, err)
	}
}

type comparisonHarness struct {
	tenantID          shared.ID
	cycleID           shared.ID
	assessmentID      shared.ID
	targetCanonical   string
	snapshotsByNumber map[int]*assessmentsnapshot.Snapshot
	comparisons       *memory.AssessmentComparisonRepository
	snapshots         *memory.AssessmentSnapshotRepository
	cycles            *memory.AssessmentCycleRepository
	lineage           *memory.FindingLineageRepository
	verification      *comparisonVerificationReader
	clock             *comparisonClock
	audit             *comparisonAudit
	observer          *comparisonObserver
	service           *Service
	candidate         findinglineage.MatchCandidate
}

func newComparisonHarness(t *testing.T) *comparisonHarness {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	harness := &comparisonHarness{
		tenantID: "tenant", cycleID: "cycle", assessmentID: "assessment",
		snapshotsByNumber: map[int]*assessmentsnapshot.Snapshot{}, comparisons: memory.NewAssessmentComparisonRepository(),
		snapshots: memory.NewAssessmentSnapshotRepository(), cycles: memory.NewAssessmentCycleRepository(), lineage: memory.NewFindingLineageRepository(),
		clock: &comparisonClock{now: now}, audit: &comparisonAudit{}, observer: &comparisonObserver{},
	}
	cycle, err := assessmentcycle.NewAssessmentCycle(harness.cycleID, harness.tenantID, "Cycle", assessmentcycle.BoundaryStandalone, "", "", harness.assessmentID, "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	member, err := assessmentcycle.NewInitialMember(harness.tenantID, harness.cycleID, harness.assessmentID, "operator", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.cycles.CreateCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	if err := harness.cycles.CreateMember(ctx, member); err != nil {
		t.Fatal(err)
	}
	for number, marker := range []string{"a", "b", "c"} {
		snapshot := createComparisonSnapshot(t, harness, number+1, marker, int64(number))
		harness.snapshotsByNumber[number+1] = snapshot
	}

	reopenedIdentity, reopenedFirst := comparisonLineagePair(t, harness, "reopened", harness.snapshotsByNumber[1].ID, "observation-reopened-first", shared.SeverityHigh, 8000, now)
	createIdentity(t, harness.lineage, reopenedIdentity, reopenedFirst)
	reopenedCurrent := comparisonObservation(harness, reopenedIdentity.ID, harness.snapshotsByNumber[3].ID, "observation-reopened-current", "source-reopened-current", shared.SeverityMedium, 5000, now.Add(3*time.Minute))
	appendObservation(t, harness.lineage, reopenedCurrent)

	fixedIdentity, fixedBaseline := comparisonLineagePair(t, harness, "fixed", harness.snapshotsByNumber[2].ID, "observation-fixed-baseline", shared.SeverityHigh, 7000, now.Add(time.Minute))
	createIdentity(t, harness.lineage, fixedIdentity, fixedBaseline)

	stillIdentity, stillBaseline := comparisonLineagePair(t, harness, "still", harness.snapshotsByNumber[2].ID, "observation-still-baseline", shared.SeverityHigh, 6000, now.Add(time.Minute))
	createIdentity(t, harness.lineage, stillIdentity, stillBaseline)
	stillCurrent := comparisonObservation(harness, stillIdentity.ID, harness.snapshotsByNumber[3].ID, "observation-still-current", "source-still-current", shared.SeverityMedium, 4000, now.Add(3*time.Minute))
	appendObservation(t, harness.lineage, stillCurrent)

	newIdentity, newCurrent := comparisonLineagePair(t, harness, "new", harness.snapshotsByNumber[3].ID, "observation-new-current", shared.SeverityMedium, 3000, now.Add(3*time.Minute))
	createIdentity(t, harness.lineage, newIdentity, newCurrent)

	ambiguousIdentity, ambiguousCurrent := comparisonLineagePair(t, harness, "ambiguous", harness.snapshotsByNumber[3].ID, "observation-ambiguous-current", shared.SeverityMedium, 2000, now.Add(3*time.Minute))
	createIdentity(t, harness.lineage, ambiguousIdentity, ambiguousCurrent)
	harness.candidate = comparisonCandidate(t, harness, ambiguousIdentity.ID, harness.snapshotsByNumber[3].ID, now.Add(4*time.Minute))
	if _, created, err := harness.lineage.CreateCandidate(ctx, harness.candidate, ""); err != nil || !created {
		t.Fatalf("candidate created=%v err=%v", created, err)
	}

	overrideTargetIdentity, overrideBaseline := comparisonLineagePair(t, harness, "override-target", harness.snapshotsByNumber[2].ID, "observation-override-target-baseline", shared.SeverityHigh, 5000, now.Add(time.Minute))
	createIdentity(t, harness.lineage, overrideTargetIdentity, overrideBaseline)
	overrideSourceIdentity, overrideCurrent := comparisonLineagePair(t, harness, "override-source", harness.snapshotsByNumber[3].ID, "observation-override-source-current", shared.SeverityMedium, 4000, now.Add(3*time.Minute))
	createIdentity(t, harness.lineage, overrideSourceIdentity, overrideCurrent)
	override, err := findinglineage.NewOverrideEvent(findinglineage.OverrideEvent{
		TenantID: harness.tenantID, CycleID: harness.cycleID, ID: "override-current-source", Action: findinglineage.OverrideConfirm,
		SourceObservationID: overrideCurrent.ID, SourceIdentityID: overrideSourceIdentity.ID, TargetIdentityID: overrideTargetIdentity.ID,
		Actor: "reviewer", Reason: "confirmed lineage", ExpectedVersion: 0, Version: 1, CreatedAt: now.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, applied, err := harness.lineage.AppendOverrideCAS(ctx, override); err != nil || !applied {
		t.Fatalf("override applied=%v err=%v", applied, err)
	}

	harness.verification = &comparisonVerificationReader{decisions: []ports.AssessmentComparisonVerification{{
		ID: "verification-reopened", IdentityID: reopenedIdentity.ID, EffectiveSnapshotID: harness.snapshotsByNumber[2].ID, State: "remediated", Remediated: true,
	}}}
	harness.service, err = NewService(harness.comparisons, harness.snapshots, harness.cycles, harness.lineage, memory.NewTenantTransactionRunner(), harness.audit, harness.clock, &comparisonIDs{}, harness.verification, harness.observer)
	if err != nil {
		t.Fatal(err)
	}
	return harness
}

func createComparisonSnapshot(t *testing.T, harness *comparisonHarness, number int, marker string, expectedVersion int64) *assessmentsnapshot.Snapshot {
	t.Helper()
	started := harness.clock.Now()
	finished := started.Add(time.Minute)
	target, err := scanrun.CanonicalizeRepositoryTarget("https://example.com/repo.git", strings.Repeat(marker, 40))
	if err != nil {
		t.Fatal(err)
	}
	harness.targetCanonical = target.TargetIdentityCanonical
	run := scanrun.ScanRun{
		TenantID: harness.tenantID, ID: fmt.Sprintf("run-%d", number), EngagementID: harness.assessmentID, CreatedAt: started, UpdatedAt: started,
		Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusBuilding,
		ManifestSchemaVersion: scanrun.CurrentManifestSchemaVersion,
		Lanes: []scanrun.Lane{{
			TenantID: harness.tenantID, EngagementID: harness.assessmentID, ScanRunID: fmt.Sprintf("run-%d", number), LaneKey: "sca", Producer: "sca", TerminalStatus: scanrun.StatusSucceeded, Target: target,
			AuthoritativeFindingKinds: []string{"vulnerability"}, IncludedScope: []string{"src/**"}, ExcludedScope: []string{"vendor/**"},
			StartedAt: started, FinishedAt: &finished, ResultRef: fmt.Sprintf("result-%d", number), EvidenceRef: fmt.Sprintf("evidence-%d", number),
			ResultSHA256: strings.Repeat(marker, 64), ManifestSchemaVersion: scanrun.CurrentManifestSchemaVersion,
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
	snapshot, err := assessmentsnapshot.NewFinalized(harness.tenantID, shared.ID(fmt.Sprintf("snapshot-%d", number)), harness.cycleID, harness.assessmentID,
		assessmentsnapshot.Boundary{Kind: assessmentcycle.BoundaryStandalone}, fmt.Sprintf("request-%d", number), "operator", finished,
		[]assessmentsnapshot.SelectedRun{{ID: run.ID, ManifestHash: run.ManifestHash, Provenance: run.Provenance, TerminalStatus: run.TerminalStatus, Trusted: true, Lanes: run.Lanes}})
	if err != nil {
		t.Fatal(err)
	}
	stored, created, err := harness.snapshots.CreateFinalizedCAS(context.Background(), snapshot, expectedVersion)
	if err != nil || !created {
		t.Fatalf("snapshot %d created=%v err=%v", number, created, err)
	}
	return stored
}

func comparisonLineagePair(t *testing.T, harness *comparisonHarness, identityID string, snapshotID shared.ID, observationID string, severity shared.Severity, risk int, now time.Time) (findinglineage.Identity, findinglineage.Observation) {
	t.Helper()
	canonical, err := findinglineage.CanonicalizeFingerprintV1(findinglineage.FingerprintCanonicalInputV1{
		CanonicalizationVersion: 1, ProducerKind: "sca", TargetIdentitySchemaVersion: 1, TargetIdentityCanonical: harness.targetCanonical,
		IdentityFields: map[string]findinglineage.CanonicalValue{"rule_id": findinglineage.Text("rule-" + identityID)},
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := findinglineage.Identity{
		TenantID: harness.tenantID, CycleID: harness.cycleID, ID: shared.ID(identityID), ProducerKind: "sca", FindingKind: "vulnerability",
		CanonicalizationVersion: 1, FingerprintSchemaVersion: 1, LineageFingerprint: canonical.Fingerprint,
		TargetIdentitySchemaVersion: 1, TargetIdentityCanonical: harness.targetCanonical, CanonicalIdentityFields: canonical.IdentityFields,
		FirstSeenSnapshotID: snapshotID, CreatedAt: now,
	}
	return identity, comparisonObservation(harness, identity.ID, snapshotID, observationID, "source-"+observationID, severity, risk, now)
}

func comparisonObservation(harness *comparisonHarness, identityID, snapshotID shared.ID, observationID, sourceID string, severity shared.Severity, risk int, now time.Time) findinglineage.Observation {
	return findinglineage.Observation{
		TenantID: harness.tenantID, CycleID: harness.cycleID, ID: shared.ID(observationID), SnapshotID: snapshotID, IdentityID: identityID,
		ProducerKind: "sca", FindingKind: "vulnerability", TargetCanonical: harness.targetCanonical, SourceFindingID: sourceID,
		Severity: severity, RiskScoreMilli: &risk, ComponentVersion: "1.0.0", Location: "go.mod", Reachability: "reachable",
		EvidenceDigest: strings.Repeat("a", 64), ScannerProvenance: findinglineage.ScannerProvenance{ToolName: "sca", ToolVersion: "1", LaneKey: "sca", RuleID: "rule-" + identityID.String()},
		ObservedAt: now,
	}
}

func createIdentity(t *testing.T, repository *memory.FindingLineageRepository, identity findinglineage.Identity, observation findinglineage.Observation) {
	t.Helper()
	if err := repository.CreateIdentityWithObservation(context.Background(), identity, observation); err != nil {
		t.Fatal(err)
	}
}

func appendObservation(t *testing.T, repository *memory.FindingLineageRepository, observation findinglineage.Observation) {
	t.Helper()
	if err := repository.AppendObservation(context.Background(), observation); err != nil {
		t.Fatal(err)
	}
}

func comparisonCandidate(t *testing.T, harness *comparisonHarness, identityID, snapshotID shared.ID, now time.Time) findinglineage.MatchCandidate {
	t.Helper()
	sourceHash := strings.Repeat("f", 64)
	candidate, err := findinglineage.NewMatchCandidate(findinglineage.MatchCandidate{
		TenantID: harness.tenantID, CycleID: harness.cycleID, SnapshotID: snapshotID, ID: "candidate-ambiguous",
		ProducerKind: "sca", FindingKind: "vulnerability", Reason: findinglineage.ReasonFingerprintCollision,
		FingerprintSchemaVersion: 1, Fingerprint: strings.Repeat("e", 64), SourceReferenceHash: sourceHash,
		Refs: []findinglineage.CandidateRef{
			{Position: 0, Role: findinglineage.RoleSource, ExternalReferenceHash: sourceHash, Method: findinglineage.MethodMatcher, ScoreMilli: 1000, Confidence: findinglineage.ConfidenceHigh},
			{Position: 1, Role: findinglineage.RoleCandidate, IdentityID: identityID, Method: findinglineage.MethodFingerprint, ScoreMilli: 900, Confidence: findinglineage.ConfidenceHigh},
		},
		CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func comparisonItem(t *testing.T, comparison assessmentcomparison.Comparison, identityID shared.ID) assessmentcomparison.Item {
	t.Helper()
	for _, item := range comparison.Items {
		if item.IdentityID == identityID {
			return item
		}
	}
	t.Fatalf("comparison item %s not found", identityID)
	return assessmentcomparison.Item{}
}

func assertPresence(t *testing.T, comparison assessmentcomparison.Comparison, identityID shared.ID, want assessmentcomparison.Presence) {
	t.Helper()
	if item := comparisonItem(t, comparison, identityID); item.Presence != want {
		t.Fatalf("identity=%s presence=%s want=%s item=%+v", identityID, item.Presence, want, item)
	}
}

type comparisonClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *comparisonClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(time.Second)
	return clock.now
}

type comparisonIDs struct {
	mu   sync.Mutex
	next int
}

func (ids *comparisonIDs) NewID() shared.ID {
	ids.mu.Lock()
	defer ids.mu.Unlock()
	ids.next++
	return shared.ID(fmt.Sprintf("comparison-%d", ids.next))
}

type comparisonVerificationReader struct {
	decisions []ports.AssessmentComparisonVerification
	err       error
}

func (reader *comparisonVerificationReader) ListEffectiveComparisonVerifications(context.Context, shared.ID, shared.ID, []shared.ID) ([]ports.AssessmentComparisonVerification, error) {
	if reader.err != nil {
		return nil, reader.err
	}
	return append([]ports.AssessmentComparisonVerification(nil), reader.decisions...), nil
}

type comparisonAudit struct {
	mu      sync.Mutex
	entries []ports.AuditEntry
}

func (audit *comparisonAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	audit.entries = append(audit.entries, entry)
	return nil
}

type comparisonObserver struct {
	mu      sync.Mutex
	entries [][3]string
}

func (observer *comparisonObserver) ObserveAssessmentComparison(status, mode, reason string) {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	observer.entries = append(observer.entries, [3]string{status, mode, reason})
}
