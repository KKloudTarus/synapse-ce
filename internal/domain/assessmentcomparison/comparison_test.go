package assessmentcomparison

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestDecidePairPartialOrderAndModes(t *testing.T) {
	members := []assessmentcycle.Member{
		{TenantID: "tenant", CycleID: "cycle", AssessmentID: "root", AssessmentType: assessmentcycle.AssessmentTypeInitial, RelationshipVersion: 1},
		{TenantID: "tenant", CycleID: "cycle", AssessmentID: "left", AssessmentType: assessmentcycle.AssessmentTypeRetest, PredecessorAssessmentID: "root", RetestNumber: 1, RelationshipVersion: 2},
		{TenantID: "tenant", CycleID: "cycle", AssessmentID: "right", AssessmentType: assessmentcycle.AssessmentTypeRetest, PredecessorAssessmentID: "root", RetestNumber: 2, RelationshipVersion: 1},
	}
	rootOne := comparisonSnapshot("root-1", "cycle", "root", 1)
	rootTwo := comparisonSnapshot("root-2", "cycle", "root", 2)
	left := comparisonSnapshot("left-1", "cycle", "left", 1)
	right := comparisonSnapshot("right-1", "cycle", "right", 1)

	for _, testCase := range []struct {
		name              string
		mode              Mode
		baseline, current *assessmentsnapshot.Snapshot
		allowed           bool
		reason            string
	}{
		{name: "same assessment forward", mode: ModeLifecycle, baseline: rootOne, current: rootTwo, allowed: true, reason: ReasonDirected},
		{name: "same assessment reverse", mode: ModeLifecycle, baseline: rootTwo, current: rootOne, reason: ReasonLifecycleReverse},
		{name: "same assessment reverse neutral", mode: ModeNeutral, baseline: rootTwo, current: rootOne, allowed: true, reason: ReasonNeutralReverse},
		{name: "ancestor forward", mode: ModeLifecycle, baseline: rootTwo, current: left, allowed: true, reason: ReasonDirected},
		{name: "ancestor reverse", mode: ModeLifecycle, baseline: left, current: rootTwo, reason: ReasonLifecycleReverse},
		{name: "siblings lifecycle", mode: ModeLifecycle, baseline: left, current: right, reason: ReasonLifecycleSibling},
		{name: "siblings neutral", mode: ModeNeutral, baseline: left, current: right, allowed: true, reason: ReasonNeutralSibling},
		{name: "directed neutral rejected", mode: ModeNeutral, baseline: rootTwo, current: left, reason: ReasonLifecycleDirectionAvailable},
		{name: "same snapshot", mode: ModeLifecycle, baseline: rootOne, current: rootOne, reason: ReasonSameSnapshot},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			decision, err := DecidePair(testCase.mode, testCase.baseline, testCase.current, members)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Allowed != testCase.allowed || decision.ReasonCode != testCase.reason {
				t.Fatalf("decision=%+v", decision)
			}
		})
	}

	crossCycle := comparisonSnapshot("other", "other-cycle", "right", 1)
	decision, err := DecidePair(ModeNeutral, left, crossCycle, members)
	if err != nil || decision.ReasonCode != ReasonCrossCycle {
		t.Fatalf("cross-cycle decision=%+v err=%v", decision, err)
	}
	missing := comparisonSnapshot("missing", "cycle", "missing-assessment", 1)
	decision, err = DecidePair(ModeLifecycle, rootOne, missing, members)
	if err != nil || decision.ReasonCode != ReasonMissingRelationship {
		t.Fatalf("missing relationship decision=%+v err=%v", decision, err)
	}
}

func TestLifecycleAndNeutralClassification(t *testing.T) {
	baseline := comparisonObservation("baseline", shared.SeverityMedium)
	current := comparisonObservation("current", shared.SeverityHigh)
	current.ComponentVersion = "2.0.0"
	current.Location = "src/b.go"
	current.Reachability = "high"
	current.EvidenceDigest = strings.Repeat("b", 64)
	current.ScannerProvenance = findinglineage.ScannerProvenance{ToolName: "scanner-2", ToolVersion: "2", LaneKey: "profile-2", RuleID: "GHSA-2"}

	item, err := ClassifyLifecycle(ClassifyInput{IdentityID: "identity", Baseline: &baseline, Current: &current})
	if err != nil {
		t.Fatal(err)
	}
	if item.Presence != PresenceDetected || len(item.ChangeFlags) != 8 || item.ChangeFlags[0] != SeverityIncreased {
		t.Fatalf("changed item=%+v", item)
	}

	fixed, err := ClassifyLifecycle(ClassifyInput{
		IdentityID: "fixed", Baseline: &baseline, CurrentCoverage: assessmentsnapshot.Comparable,
		BaselineActionable: true, BaselineRiskMilli: 9000,
	})
	if err != nil || fixed.Presence != PresenceNotDetected || !fixed.ComparableBaseline || fixed.FixedBasis != FixedByComparableAbsence {
		t.Fatalf("fixed=%+v err=%v", fixed, err)
	}
	verified, err := ClassifyLifecycle(ClassifyInput{
		IdentityID: "verified", Baseline: &baseline, CurrentCoverage: assessmentsnapshot.NotComparable,
		VerificationID: "verification-1", VerificationState: "remediated", VerificationRemediated: true,
	})
	if err != nil || verified.Presence != PresenceNotEvaluated || verified.FixedBasis != FixedByExplicitVerification {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}
	notEvaluated, err := ClassifyLifecycle(ClassifyInput{IdentityID: "unknown", Baseline: &baseline, CurrentCoverage: assessmentsnapshot.PartiallyComparable})
	if err != nil || notEvaluated.Presence != PresenceNotEvaluated {
		t.Fatalf("not evaluated=%+v err=%v", notEvaluated, err)
	}
	newItem, err := ClassifyLifecycle(ClassifyInput{IdentityID: "new", Current: &current})
	if err != nil || newItem.Presence != PresenceNew {
		t.Fatalf("new=%+v err=%v", newItem, err)
	}
	reopened, err := ClassifyLifecycle(ClassifyInput{
		IdentityID: "reopened", Current: &current,
		History: []HistoryState{{Order: 1, Observed: true}, {Order: 2, ComparableAbsence: true, VerificationDecision: "verification-1"}},
	})
	if err != nil || reopened.Presence != PresenceReopened {
		t.Fatalf("reopened=%+v err=%v", reopened, err)
	}
	reviewHistory, err := ClassifyLifecycle(ClassifyInput{
		IdentityID: "history-review", Current: &current,
		History: []HistoryState{{Order: 1, Ambiguous: true}, {Order: 2, Observed: true}},
	})
	if err != nil || reviewHistory.Presence != PresenceNeedsReview {
		t.Fatalf("history review=%+v err=%v", reviewHistory, err)
	}
	ambiguous, err := ClassifyLifecycle(ClassifyInput{IdentityID: "ambiguous", Current: &current, Ambiguous: true})
	if err != nil || ambiguous.Presence != PresenceNeedsReview {
		t.Fatalf("ambiguous=%+v err=%v", ambiguous, err)
	}

	neutral, err := ClassifyNeutral(ClassifyInput{IdentityID: "neutral", Baseline: &baseline, Current: &current})
	if err != nil || neutral.NeutralPresence != NeutralBoth || neutral.Presence != "" {
		t.Fatalf("neutral=%+v err=%v", neutral, err)
	}
}

func TestSummaryAndGenerationHashAreStable(t *testing.T) {
	items := []Item{
		{IdentityID: "fixed", Presence: PresenceNotDetected, BaselineActionable: true, ComparableBaseline: true, BaselineRiskMilli: 8000},
		{IdentityID: "still", Presence: PresenceDetected, BaselineActionable: true, CurrentActionable: true, ComparableBaseline: true, BaselineRiskMilli: 7000, CurrentRiskMilli: 5000},
		{IdentityID: "new", Presence: PresenceNew, CurrentActionable: true, CurrentRiskMilli: 2000},
	}
	summary := Summarize(items)
	if summary.FixedRate != (Ratio{Numerator: 1, Denominator: 2}) || summary.CountReduction != (Ratio{Numerator: 0, Denominator: 2}) || summary.RiskReduction != (Ratio{Numerator: 8000, Denominator: 15000}) {
		t.Fatalf("summary=%+v", summary)
	}

	input := GenerationInput{
		Mode:     ModeLifecycle,
		Baseline: SnapshotHashRef{ID: "baseline", ContentHash: strings.Repeat("a", 64)},
		Current:  SnapshotHashRef{ID: "current", ContentHash: strings.Repeat("b", 64)},
		Relationships: []RelationshipRef{
			{AssessmentID: "root", RelationshipVersion: 1},
			{AssessmentID: "retest", PredecessorID: "root", RelationshipVersion: 2},
		},
		AlgorithmVersion: 1, FingerprintVersion: 1, RiskModelVersion: 3, CoveragePolicyVersion: 1,
		ActiveOverrideIDs: []shared.ID{"override-b", "override-a"}, VerificationDecisionIDs: []shared.ID{"verify-1"},
	}
	canonical, digest, err := HashGenerationInput(input)
	if err != nil {
		t.Fatal(err)
	}
	const wantDigest = "028407bed04d1e8231001dfc29fc7c2ea0a5655a535624c50c936ec062086750"
	if digest != wantDigest {
		t.Fatalf("digest=%s want=%s canonical=%s", digest, wantDigest, canonical)
	}
	reordered := input
	reordered.ActiveOverrideIDs = []shared.ID{"override-a", "override-b", "override-a"}
	_, replayDigest, err := HashGenerationInput(reordered)
	if err != nil || replayDigest != digest {
		t.Fatalf("replay digest=%s err=%v", replayDigest, err)
	}
}

func comparisonSnapshot(id, cycleID, assessmentID string, number int) *assessmentsnapshot.Snapshot {
	return &assessmentsnapshot.Snapshot{
		TenantID: "tenant", ID: shared.ID(id), CycleID: shared.ID(cycleID), AssessmentID: shared.ID(assessmentID),
		SnapshotNumber: number, Lifecycle: assessmentsnapshot.LifecycleFinalized,
	}
}

func comparisonObservation(id string, severity shared.Severity) findinglineage.Observation {
	return findinglineage.Observation{
		ID: shared.ID(id), Severity: severity, ComponentVersion: "1.0.0", Location: "src/a.go", Reachability: "medium",
		EvidenceDigest: strings.Repeat("a", 64), ScannerProvenance: findinglineage.ScannerProvenance{
			ToolName: "scanner-1", ToolVersion: "1", LaneKey: "profile-1", RuleID: "CVE-1",
		},
	}
}
