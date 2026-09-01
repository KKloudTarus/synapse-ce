package assessmentclosure

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestEvaluateFailsClosedAndRequiresExactOverrides(t *testing.T) {
	cycle, initial, final, comparison := closureFixtures()
	initial.Dimensions = []assessmentsnapshot.Dimension{{
		Target:   assessmentsnapshot.Target{Kind: scanrun.TargetRepository, Canonical: "repo"},
		Producer: "sca", FindingKind: "vulnerability", State: assessmentsnapshot.CoveragePartial, ReasonCode: assessmentsnapshot.ReasonRunPartial,
	}}
	comparison.Items = []assessmentcomparison.Item{{
		ID: "finding-high", CurrentActionable: true,
		CurrentObservation: assessmentcomparison.ObservationView{Severity: shared.SeverityHigh},
	}}

	result := Evaluate(PolicyInput{Cycle: cycle, FinalStatus: engagement.StatusCompleted, InitialSnapshot: initial, FinalSnapshot: final, Comparison: comparison})
	if result.CommitAllowed {
		t.Fatal("closure with incomplete coverage and actionable High finding must fail closed")
	}
	overrides := overrideableIDs(result.Blockers)
	if len(overrides) != 2 {
		t.Fatalf("overrideable blockers=%v, want coverage and High finding", overrides)
	}

	result = Evaluate(PolicyInput{
		Cycle: cycle, FinalStatus: engagement.StatusCompleted, InitialSnapshot: initial, FinalSnapshot: final, Comparison: comparison,
		OverrideBlockerIDs: overrides, OverrideReason: "approved exception",
	})
	if !result.CommitAllowed || !result.CoverageDecisions.Initial[0].Waived {
		t.Fatalf("valid exact overrides should allow commit and waive coverage: %+v", result)
	}

	cycle.Status = assessmentcycle.StatusCompleted
	result = Evaluate(PolicyInput{
		Cycle: cycle, FinalStatus: engagement.StatusCompleted, InitialSnapshot: initial, FinalSnapshot: final, Comparison: comparison,
		OverrideBlockerIDs: []string{"cycle:not_open"}, OverrideReason: "must not bypass integrity",
	})
	if result.CommitAllowed || !hasBlockerCode(result.Blockers, "override_hard_blocker") {
		t.Fatalf("hard blocker override must fail closed: %+v", result.Blockers)
	}
}

func TestEvaluateMissingArtifactsAndUnknownOverrideFailClosed(t *testing.T) {
	cycle, _, _, _ := closureFixtures()
	result := Evaluate(PolicyInput{
		Cycle: cycle, FinalStatus: engagement.StatusCompleted,
		OverrideBlockerIDs: []string{"coverage:made-up"}, OverrideReason: "invalid",
	})
	for _, code := range []string{"initial_snapshot_missing", "final_snapshot_missing", "comparison_missing", "override_unknown"} {
		if !hasBlockerCode(result.Blockers, code) {
			t.Fatalf("missing blocker %q in %+v", code, result.Blockers)
		}
	}
	if result.CommitAllowed {
		t.Fatal("missing immutable artifacts must fail closed")
	}
}

func TestEvaluateExpiredDecisionAndIncompleteVerificationFailClosed(t *testing.T) {
	cycle, initial, final, comparison := closureFixtures()
	comparison.Items = []assessmentcomparison.Item{{ID: "finding", VerificationID: "verification", VerificationState: "pending"}}
	asOfAt := time.Date(2026, 9, 1, 4, 0, 0, 0, time.UTC)
	expiresAt := asOfAt.Add(-time.Second)
	result := Evaluate(PolicyInput{
		Cycle: cycle, FinalStatus: engagement.StatusCompleted, InitialSnapshot: initial, FinalSnapshot: final, Comparison: comparison, AsOfAt: asOfAt,
		References: []Reference{{Kind: "accepted_risk", ID: "risk", Version: 1, ExpiresAt: &expiresAt}},
	})
	for _, code := range []string{"verification_incomplete", "decision_expired"} {
		if !hasBlockerCode(result.Blockers, code) {
			t.Fatalf("missing blocker %q in %+v", code, result.Blockers)
		}
	}
	if result.CommitAllowed {
		t.Fatal("expired decision and incomplete verification must fail closed")
	}
}

func TestManifestCanonicalHashAndTamperDetection(t *testing.T) {
	cycle, initial, final, comparison := closureFixtures()
	now := time.Date(2026, 9, 2, 4, 0, 0, 0, time.UTC)
	base := ManifestInput{
		TenantID: cycle.TenantID, CycleID: cycle.ID, ManifestVersion: 1, CycleVersion: cycle.Version + 1,
		RootAssessmentID: cycle.RootAssessmentID, FinalAssessmentID: cycle.SelectedHeadAssessmentID,
		InitialSnapshot: initial, FinalSnapshot: final, Comparison: comparison,
		CoverageDecisions: CoverageDecisions{
			Initial: []CoverageDecision{
				{SnapshotID: initial.ID, DimensionID: "z", State: assessmentsnapshot.CoverageComplete},
				{SnapshotID: initial.ID, DimensionID: "a", State: assessmentsnapshot.CoverageComplete},
			},
			Final: []CoverageDecision{{SnapshotID: final.ID, DimensionID: "final", State: assessmentsnapshot.CoverageComplete}},
		},
		ScopeProfileChanges: []ScopeProfileChange{{AssessmentID: "final", Kind: "scope", Summary: "changed"}, {AssessmentID: "root", Kind: "profile", Summary: "initial"}},
		OverrideBlockerIDs:  []string{"finding:b", "finding:a", "finding:a"},
		NonFinalBranches:    []BranchState{{AssessmentID: "branch-b", RelationshipVersion: 2}, {AssessmentID: "branch-a", RelationshipVersion: 1}},
		Path: []PathMember{
			{PathPosition: 1, AssessmentID: "final", AssessmentType: assessmentcycle.AssessmentTypeRetest, RetestNumber: 1, RelationshipVersion: 2, SnapshotID: final.ID},
			{PathPosition: 0, AssessmentID: "root", AssessmentType: assessmentcycle.AssessmentTypeInitial, RelationshipVersion: 1, SnapshotID: initial.ID},
		},
		References: []Reference{
			{Kind: "verification", ID: "verification-2", Version: 2, Metadata: json.RawMessage(`{"b":2,"a":1}`)},
			{Kind: "accepted_risk", ID: "risk-1", Version: 1, Metadata: json.RawMessage(`{"state":"active"}`)},
		},
		Reason: "finalized", OverrideReason: "approved", AsOfAt: now.Add(-time.Minute), CreatedAt: now, CreatedBy: "reviewer",
	}

	first, err := NewManifest("manifest-1", base)
	if err != nil {
		t.Fatalf("new manifest: %v", err)
	}
	reordered := base
	reordered.CoverageDecisions.Initial = reverseCoverage(base.CoverageDecisions.Initial)
	reordered.ScopeProfileChanges = reverseScope(base.ScopeProfileChanges)
	reordered.OverrideBlockerIDs = []string{"finding:a", "finding:b"}
	reordered.NonFinalBranches = reverseBranches(base.NonFinalBranches)
	reordered.Path = reversePath(base.Path)
	reordered.References = []Reference{
		{Kind: "accepted_risk", ID: "risk-1", Version: 1, Metadata: json.RawMessage(`{"state":"active"}`)},
		{Kind: "verification", ID: "verification-2", Version: 2, Metadata: json.RawMessage(`{"a":1,"b":2}`)},
	}
	second, err := NewManifest("manifest-1", reordered)
	if err != nil {
		t.Fatalf("new reordered manifest: %v", err)
	}
	if first.CanonicalInputHash != second.CanonicalInputHash {
		t.Fatalf("canonical input hash changed for equivalent input: %s != %s", first.CanonicalInputHash, second.CanonicalInputHash)
	}
	sealedAt := now.Add(time.Second)
	if err := first.Seal(sealedAt, "reviewer"); err != nil {
		t.Fatalf("seal manifest: %v", err)
	}
	if err := second.Seal(sealedAt, "reviewer"); err != nil {
		t.Fatalf("seal reordered manifest: %v", err)
	}
	if first.ContentHash != second.ContentHash {
		t.Fatalf("content hash changed for equivalent input: %s != %s", first.ContentHash, second.ContentHash)
	}
	first.Reason = "tampered"
	if err := first.Validate(); err == nil || !strings.Contains(err.Error(), "content hash mismatch") {
		t.Fatalf("tampered manifest must fail content hash validation, got %v", err)
	}
}

func closureFixtures() (*assessmentcycle.AssessmentCycle, *assessmentsnapshot.Snapshot, *assessmentsnapshot.Snapshot, *assessmentcomparison.Comparison) {
	const hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const hashC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	cycle := &assessmentcycle.AssessmentCycle{
		TenantID: "tenant", ID: "cycle", Status: assessmentcycle.StatusOpen, RootAssessmentID: "root", SelectedHeadAssessmentID: "final", Version: 7,
	}
	initial := &assessmentsnapshot.Snapshot{TenantID: "tenant", CycleID: "cycle", ID: "snapshot-root", AssessmentID: "root", Lifecycle: assessmentsnapshot.LifecycleFinalized, ContentHash: hashA}
	final := &assessmentsnapshot.Snapshot{TenantID: "tenant", CycleID: "cycle", ID: "snapshot-final", AssessmentID: "final", Lifecycle: assessmentsnapshot.LifecycleFinalized, ContentHash: hashB}
	comparison := &assessmentcomparison.Comparison{
		TenantID: "tenant", CycleID: "cycle", ID: "comparison", BaselineSnapshotID: initial.ID, CurrentSnapshotID: final.ID,
		Mode: assessmentcomparison.ModeLifecycle, Status: assessmentcomparison.StatusComplete, ContentHash: hashC,
		AlgorithmVersion: 1, FingerprintVersion: 1, RiskModelVersion: 1,
	}
	return cycle, initial, final, comparison
}

func overrideableIDs(blockers []Blocker) []string {
	var ids []string
	for _, blocker := range blockers {
		if blocker.Overrideable {
			ids = append(ids, blocker.ID)
		}
	}
	return ids
}

func hasBlockerCode(blockers []Blocker, code string) bool {
	for _, blocker := range blockers {
		if blocker.Code == code {
			return true
		}
	}
	return false
}

func reverseCoverage(values []CoverageDecision) []CoverageDecision {
	return []CoverageDecision{values[1], values[0]}
}

func reverseScope(values []ScopeProfileChange) []ScopeProfileChange {
	return []ScopeProfileChange{values[1], values[0]}
}

func reverseBranches(values []BranchState) []BranchState {
	return []BranchState{values[1], values[0]}
}

func reversePath(values []PathMember) []PathMember {
	return []PathMember{values[1], values[0]}
}
