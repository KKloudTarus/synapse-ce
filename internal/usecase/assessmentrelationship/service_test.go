package assessmentrelationship

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	relationshipdom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentrelationship"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const relationshipImportedHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestGenerateRequiresExactBoundaryPlusStrongSignal(t *testing.T) {
	harness := newRelationshipHarness(t, false)
	if _, _, err := harness.service.Generate(context.Background(), harness.generateInput("")); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("exact-boundary-only generation error=%v", err)
	}

	created, wasCreated, err := harness.service.Generate(context.Background(), harness.generateInput(relationshipImportedHash))
	if err != nil || !wasCreated || created.Confidence != relationshipdom.ConfidenceMedium || !hasRelationshipSignal(created, relationshipdom.SignalImportedReference) {
		t.Fatalf("imported-reference candidate=%+v created=%v err=%v", created, wasCreated, err)
	}
	replayed, wasCreated, err := harness.service.Generate(context.Background(), harness.generateInput(relationshipImportedHash))
	if err != nil || wasCreated || replayed.ID != created.ID || replayed.InputHash != created.InputHash {
		t.Fatalf("generation replay=%+v created=%v err=%v", replayed, wasCreated, err)
	}
}

func TestGenerateUsesTrustedManifestAndDeterministicOverlapSignals(t *testing.T) {
	manifestHarness := newRelationshipHarness(t, true)
	manifest, created, err := manifestHarness.service.Generate(context.Background(), manifestHarness.generateInput(""))
	if err != nil || !created || !hasRelationshipSignal(manifest, relationshipdom.SignalTrustedManifest) || manifest.Confidence != relationshipdom.ConfidenceMedium {
		t.Fatalf("trusted manifest candidate=%+v created=%v err=%v", manifest, created, err)
	}

	overlapHarness := newRelationshipHarness(t, false)
	overlapHarness.addMatchingFindings(t, "finding-1", "finding-2")
	overlap, created, err := overlapHarness.service.Generate(context.Background(), overlapHarness.generateInput(""))
	if err != nil || !created || !hasRelationshipSignal(overlap, relationshipdom.SignalDeterministicOverlap) || overlap.Confidence != relationshipdom.ConfidenceMedium {
		t.Fatalf("overlap candidate=%+v created=%v err=%v", overlap, created, err)
	}
	for _, signal := range overlap.Signals {
		if signal.Kind == relationshipdom.SignalDeterministicOverlap && (signal.MatchCount != 2 || signal.ScoreMilli != 1000) {
			t.Fatalf("overlap signal=%+v", signal)
		}
	}
}

func TestConfirmSealsBlockedPlanWithoutChangingCycleGraph(t *testing.T) {
	harness := newRelationshipHarness(t, false)
	candidate := harness.mustGenerate(t, relationshipImportedHash)
	predecessorBefore, _ := harness.cycles.GetCycle(context.Background(), harness.tenantID, harness.predecessorCycleID)
	successorBefore, _ := harness.cycles.GetCycle(context.Background(), harness.tenantID, harness.successorCycleID)
	predecessorMembersBefore, _ := harness.cycles.ListMembers(context.Background(), harness.tenantID, harness.predecessorCycleID)
	successorMembersBefore, _ := harness.cycles.ListMembers(context.Background(), harness.tenantID, harness.successorCycleID)

	confirmed, replayed, err := harness.service.Decide(context.Background(), DecideInput{
		TenantID: harness.tenantID, CandidateID: candidate.ID, ExpectedVersion: candidate.Version,
		IdempotencyKey: "confirm-1", Action: relationshipdom.DecisionConfirm, Reason: "Validated imported migration reference", Actor: "reviewer",
	})
	if err != nil || replayed || confirmed.Status != StatusConfirmed || confirmed.Version != 2 || confirmed.RepairPlan == nil {
		t.Fatalf("confirmed=%+v replayed=%v err=%v", confirmed, replayed, err)
	}
	var planBody map[string]any
	if err := json.Unmarshal(confirmed.RepairPlan.Body, &planBody); err != nil {
		t.Fatal(err)
	}
	if planBody["execution"] != "blocked" || planBody["requires"] != "separately_approved_move_merge_command" || planBody["command"] != "assessment_cycle.merge_legacy_relationship" {
		t.Fatalf("repair plan body=%v", planBody)
	}

	predecessorAfter, _ := harness.cycles.GetCycle(context.Background(), harness.tenantID, harness.predecessorCycleID)
	successorAfter, _ := harness.cycles.GetCycle(context.Background(), harness.tenantID, harness.successorCycleID)
	predecessorMembersAfter, _ := harness.cycles.ListMembers(context.Background(), harness.tenantID, harness.predecessorCycleID)
	successorMembersAfter, _ := harness.cycles.ListMembers(context.Background(), harness.tenantID, harness.successorCycleID)
	if !reflect.DeepEqual(predecessorBefore, predecessorAfter) || !reflect.DeepEqual(successorBefore, successorAfter) || !reflect.DeepEqual(predecessorMembersBefore, predecessorMembersAfter) || !reflect.DeepEqual(successorMembersBefore, successorMembersAfter) {
		t.Fatal("confirming a candidate changed the Assessment Cycle graph")
	}
	if actions := harness.audit.actions(); !reflect.DeepEqual(actions, []string{"assessment_relationship.candidate_created", "assessment_relationship.candidate_confirm"}) {
		t.Fatalf("audit actions=%v", actions)
	}
}

func TestTerminalDecisionsSuppressRegeneration(t *testing.T) {
	for _, action := range []relationshipdom.DecisionAction{relationshipdom.DecisionReject, relationshipdom.DecisionDismiss} {
		t.Run(string(action), func(t *testing.T) {
			harness := newRelationshipHarness(t, false)
			candidate := harness.mustGenerate(t, relationshipImportedHash)
			decided, replayed, err := harness.service.Decide(context.Background(), DecideInput{
				TenantID: harness.tenantID, CandidateID: candidate.ID, ExpectedVersion: 1, IdempotencyKey: "terminal-" + string(action),
				Action: action, Reason: "Reviewed deterministic evidence", Actor: "reviewer",
			})
			if err != nil || replayed || decided.Status != decisionStatus(action) || decided.RepairPlan != nil {
				t.Fatalf("decided=%+v replayed=%v err=%v", decided, replayed, err)
			}
			regenerated, created, err := harness.service.Generate(context.Background(), harness.generateInput(relationshipImportedHash))
			if err != nil || created || regenerated.ID != candidate.ID || regenerated.Status != decided.Status {
				t.Fatalf("regenerated=%+v created=%v err=%v", regenerated, created, err)
			}
		})
	}
}

func TestDecisionReplayConflictsExpiryIsolationAndSecretRejection(t *testing.T) {
	harness := newRelationshipHarness(t, false)
	candidate := harness.mustGenerate(t, relationshipImportedHash)
	input := DecideInput{TenantID: harness.tenantID, CandidateID: candidate.ID, ExpectedVersion: 1, IdempotencyKey: "replay", Action: relationshipdom.DecisionConfirm, Reason: "Approved deterministic relationship", Actor: "reviewer"}
	first, replayed, err := harness.service.Decide(context.Background(), input)
	if err != nil || replayed {
		t.Fatalf("first decision=%+v replayed=%v err=%v", first, replayed, err)
	}
	second, replayed, err := harness.service.Decide(context.Background(), input)
	if err != nil || !replayed || second.Decision == nil || first.Decision == nil || second.Decision.ID != first.Decision.ID || second.RepairPlan == nil || first.RepairPlan == nil || second.RepairPlan.ID != first.RepairPlan.ID {
		t.Fatalf("decision replay=%+v replayed=%v err=%v", second, replayed, err)
	}
	mismatch := input
	mismatch.Action, mismatch.Reason = relationshipdom.DecisionReject, "Different idempotent content"
	if _, _, err := harness.service.Decide(context.Background(), mismatch); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("idempotency mismatch error=%v", err)
	}
	if _, _, err := harness.service.Decide(context.Background(), DecideInput{TenantID: harness.tenantID, CandidateID: candidate.ID, ExpectedVersion: 2, IdempotencyKey: "stale", Action: relationshipdom.DecisionReject, Reason: "Stale review", Actor: "reviewer"}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale version error=%v", err)
	}
	if _, err := harness.service.Get(context.Background(), "other-tenant", candidate.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get error=%v", err)
	}
	other, err := harness.service.List(context.Background(), "other-tenant", "all", 10)
	if err != nil || len(other) != 0 {
		t.Fatalf("cross-tenant list=%+v err=%v", other, err)
	}

	secretHarness := newRelationshipHarness(t, false)
	secretCandidate := secretHarness.mustGenerate(t, relationshipImportedHash)
	if _, _, err := secretHarness.service.Decide(context.Background(), DecideInput{TenantID: secretHarness.tenantID, CandidateID: secretCandidate.ID, ExpectedVersion: 1, IdempotencyKey: "secret", Action: relationshipdom.DecisionReject, Reason: "token=super-secret", Actor: "reviewer"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("secret reason error=%v", err)
	}
	stored, err := secretHarness.service.Get(context.Background(), secretHarness.tenantID, secretCandidate.ID)
	if err != nil || stored.Status != StatusOpen || stored.Decision != nil {
		t.Fatalf("candidate after secret rejection=%+v err=%v", stored, err)
	}

	expiredHarness := newRelationshipHarness(t, false)
	expiring, created, err := expiredHarness.service.Generate(context.Background(), GenerateInput{
		TenantID: expiredHarness.tenantID, PredecessorCycleID: expiredHarness.predecessorCycleID, SuccessorCycleID: expiredHarness.successorCycleID,
		ImportedReferenceHash: relationshipImportedHash, ExpiresIn: 24 * time.Hour, Actor: "operator",
	})
	if err != nil || !created {
		t.Fatalf("expiring candidate=%+v created=%v err=%v", expiring, created, err)
	}
	expiredHarness.clock.advance(24 * time.Hour)
	if _, _, err := expiredHarness.service.Decide(context.Background(), DecideInput{TenantID: expiredHarness.tenantID, CandidateID: expiring.ID, ExpectedVersion: 1, IdempotencyKey: "expired", Action: relationshipdom.DecisionDismiss, Reason: "Expired evidence", Actor: "reviewer"}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expired decision error=%v", err)
	}
}

func TestConcurrentDecisionsAllowOnlyOneWinner(t *testing.T) {
	harness := newRelationshipHarness(t, false)
	candidate := harness.mustGenerate(t, relationshipImportedHash)
	inputs := []DecideInput{
		{TenantID: harness.tenantID, CandidateID: candidate.ID, ExpectedVersion: 1, IdempotencyKey: "race-confirm", Action: relationshipdom.DecisionConfirm, Reason: "Confirm concurrent review", Actor: "reviewer-a"},
		{TenantID: harness.tenantID, CandidateID: candidate.ID, ExpectedVersion: 1, IdempotencyKey: "race-reject", Action: relationshipdom.DecisionReject, Reason: "Reject concurrent review", Actor: "reviewer-b"},
	}
	errorsByIndex := make([]error, len(inputs))
	var wait sync.WaitGroup
	for index := range inputs {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, _, errorsByIndex[index] = harness.service.Decide(context.Background(), inputs[index])
		}(index)
	}
	wait.Wait()
	winners, conflicts := 0, 0
	for _, err := range errorsByIndex {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, shared.ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent decision error=%v", err)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatalf("concurrent outcomes winners=%d conflicts=%d errors=%v", winners, conflicts, errorsByIndex)
	}
}

type relationshipHarness struct {
	service               *Service
	store                 *memory.AssessmentRelationshipRepository
	cycles                *memory.AssessmentCycleRepository
	snapshots             *memory.AssessmentSnapshotRepository
	lineage               *memory.FindingLineageRepository
	clock                 *relationshipClock
	audit                 *relationshipAudit
	tenantID              shared.ID
	predecessorCycleID    shared.ID
	predecessorAssessment shared.ID
	predecessorSnapshot   *assessmentsnapshot.Snapshot
	successorCycleID      shared.ID
	successorAssessment   shared.ID
	successorSnapshot     *assessmentsnapshot.Snapshot
}

func newRelationshipHarness(t *testing.T, compatibleManifest bool) *relationshipHarness {
	t.Helper()
	now := time.Date(2026, 9, 2, 2, 0, 0, 0, time.UTC)
	cycles := memory.NewAssessmentCycleRepository()
	snapshots := memory.NewAssessmentSnapshotRepository()
	lineage := memory.NewFindingLineageRepository()
	store := memory.NewAssessmentRelationshipRepository()
	clock := &relationshipClock{now: now}
	audit := &relationshipAudit{}
	ids := &relationshipIDs{}
	harness := &relationshipHarness{
		store: store, cycles: cycles, snapshots: snapshots, lineage: lineage, clock: clock, audit: audit,
		tenantID: "tenant", predecessorCycleID: "cycle-predecessor", predecessorAssessment: "assessment-predecessor",
		successorCycleID: "cycle-successor", successorAssessment: "assessment-successor",
	}
	harness.predecessorSnapshot = harness.createSubject(t, harness.predecessorCycleID, harness.predecessorAssessment, "snapshot-predecessor", "run-predecessor", "src/**")
	successorScope := "app/**"
	if compatibleManifest {
		successorScope = "src/**"
	}
	harness.successorSnapshot = harness.createSubject(t, harness.successorCycleID, harness.successorAssessment, "snapshot-successor", "run-successor", successorScope)
	service, err := NewService(store, cycles, snapshots, lineage, memory.NewTenantTransactionRunner(), ids, clock, audit, nil)
	if err != nil {
		t.Fatal(err)
	}
	harness.service = service
	return harness
}

func (harness *relationshipHarness) createSubject(t *testing.T, cycleID, assessmentID, snapshotID shared.ID, runID, includedScope string) *assessmentsnapshot.Snapshot {
	t.Helper()
	cycle, err := assessmentcycle.NewAssessmentCycle(cycleID, harness.tenantID, cycleID.String(), assessmentcycle.BoundaryProject, "", "project-1", assessmentID, "operator", harness.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	member, err := assessmentcycle.NewInitialMember(harness.tenantID, cycleID, assessmentID, "operator", harness.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.cycles.CreateCycle(context.Background(), cycle); err != nil {
		t.Fatal(err)
	}
	if err := harness.cycles.CreateMember(context.Background(), member); err != nil {
		t.Fatal(err)
	}
	snapshot, err := assessmentsnapshot.NewFinalized(harness.tenantID, snapshotID, cycleID, assessmentID,
		assessmentsnapshot.Boundary{Kind: assessmentcycle.BoundaryProject, ProjectID: "project-1"}, "request-"+snapshotID.String(), "operator", harness.clock.Now(),
		[]assessmentsnapshot.SelectedRun{relationshipSelectedRun(t, runID, includedScope, harness.clock.Now())})
	if err != nil {
		t.Fatal(err)
	}
	stored, created, err := harness.snapshots.CreateFinalizedCAS(context.Background(), snapshot, 0)
	if err != nil || !created {
		t.Fatalf("create snapshot=%+v created=%v err=%v", stored, created, err)
	}
	return stored
}

func relationshipSelectedRun(t *testing.T, runID, includedScope string, now time.Time) assessmentsnapshot.SelectedRun {
	t.Helper()
	target, err := scanrun.CanonicalizeRepositoryTarget("https://example.com/repository.git", "0123456789abcdef0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	finished := now.Add(-time.Minute)
	lanes := []scanrun.Lane{{
		TenantID: "tenant", EngagementID: "assessment", ScanRunID: runID, LaneKey: "sca", Producer: "sca", TerminalStatus: scanrun.StatusSucceeded, Target: target,
		AuthoritativeFindingKinds: []string{"vulnerability"}, IncludedScope: []string{includedScope}, ExcludedScope: []string{"vendor/**"},
		StartedAt: now.Add(-2 * time.Minute), FinishedAt: &finished, ResultRef: "result:" + runID, EvidenceRef: "evidence:" + runID,
		ResultSHA256: strings.Repeat("b", 64), ManifestSchemaVersion: scanrun.CurrentManifestSchemaVersion, SealedAt: &now,
		Versions: []scanrun.LaneVersion{{VersionKind: scanrun.VersionScanner, Name: "sca", Version: "1"}}, Stages: []scanrun.LaneStage{{StageKey: "scan", Status: scanrun.StageSucceeded, StartedAt: now.Add(-2 * time.Minute), FinishedAt: &finished}},
	}}
	lanes[0].ManifestHash, err = scanrun.ComputeManifestHash(lanes[0])
	if err != nil {
		t.Fatal(err)
	}
	manifestHash, err := scanrun.ComputeRunManifestHash(lanes)
	if err != nil {
		t.Fatal(err)
	}
	return assessmentsnapshot.SelectedRun{ID: runID, ManifestHash: manifestHash, Provenance: scanrun.ProvenanceNative, TerminalStatus: scanrun.StatusSucceeded, Trusted: true, Lanes: lanes}
}

func (harness *relationshipHarness) addMatchingFindings(t *testing.T, rules ...string) {
	t.Helper()
	target := harness.predecessorSnapshot.Dimensions[0].Target.Canonical
	for _, rule := range rules {
		canonical, err := findinglineage.CanonicalizeFingerprintV1(findinglineage.FingerprintCanonicalInputV1{
			CanonicalizationVersion: 1, ProducerKind: "sca", TargetIdentitySchemaVersion: 1, TargetIdentityCanonical: target,
			IdentityFields: map[string]findinglineage.CanonicalValue{"rule_id": findinglineage.Text(rule)},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, subject := range []struct {
			cycleID, snapshotID shared.ID
			prefix              string
		}{{harness.predecessorCycleID, harness.predecessorSnapshot.ID, "predecessor"}, {harness.successorCycleID, harness.successorSnapshot.ID, "successor"}} {
			identityID := shared.ID(subject.prefix + "-identity-" + rule)
			identity := findinglineage.Identity{
				TenantID: harness.tenantID, CycleID: subject.cycleID, ID: identityID, ProducerKind: "sca", FindingKind: "vulnerability",
				CanonicalizationVersion: 1, FingerprintSchemaVersion: 1, LineageFingerprint: canonical.Fingerprint,
				TargetIdentitySchemaVersion: 1, TargetIdentityCanonical: target, CanonicalIdentityFields: canonical.IdentityFields,
				FirstSeenSnapshotID: subject.snapshotID, CreatedAt: harness.clock.Now(),
			}
			risk := 1000
			observation := findinglineage.Observation{
				TenantID: harness.tenantID, CycleID: subject.cycleID, ID: shared.ID(subject.prefix + "-observation-" + rule), SnapshotID: subject.snapshotID, IdentityID: identityID,
				ProducerKind: "sca", FindingKind: "vulnerability", TargetCanonical: target, SourceFindingID: subject.prefix + "-source-" + rule,
				Severity: shared.SeverityLow, RiskScoreMilli: &risk, EvidenceDigest: strings.Repeat("e", 64),
				ScannerProvenance: findinglineage.ScannerProvenance{ToolName: "sca", ToolVersion: "1", LaneKey: "sca", RuleID: rule}, ObservedAt: harness.clock.Now(),
			}
			if err := harness.lineage.CreateIdentityWithObservation(context.Background(), identity, observation); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func (harness *relationshipHarness) generateInput(importedHash string) GenerateInput {
	return GenerateInput{TenantID: harness.tenantID, PredecessorCycleID: harness.predecessorCycleID, SuccessorCycleID: harness.successorCycleID, ImportedReferenceHash: importedHash, Actor: "operator"}
}

func (harness *relationshipHarness) mustGenerate(t *testing.T, importedHash string) View {
	t.Helper()
	view, created, err := harness.service.Generate(context.Background(), harness.generateInput(importedHash))
	if err != nil || !created {
		t.Fatalf("generate candidate=%+v created=%v err=%v", view, created, err)
	}
	return view
}

func hasRelationshipSignal(view View, kind relationshipdom.SignalKind) bool {
	for _, signal := range view.Signals {
		if signal.Kind == kind {
			return true
		}
	}
	return false
}

type relationshipClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (clock *relationshipClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}

func (clock *relationshipClock) advance(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(duration)
}

type relationshipIDs struct{ next atomic.Int64 }

func (ids *relationshipIDs) NewID() shared.ID {
	return shared.ID(fmt.Sprintf("relationship-%d", ids.next.Add(1)))
}

type relationshipAudit struct {
	mu      sync.Mutex
	entries []ports.AuditEntry
}

func (audit *relationshipAudit) Record(_ context.Context, entry ports.AuditEntry) error {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	audit.entries = append(audit.entries, entry)
	return nil
}

func (audit *relationshipAudit) actions() []string {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	actions := make([]string, 0, len(audit.entries))
	for _, entry := range audit.entries {
		actions = append(actions, entry.Action)
	}
	return actions
}
