package assessmentcomparison

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestComparisonLifecycleCASRetryCompleteAndSupersede(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	input := GenerationInput{
		Mode:             ModeLifecycle,
		Baseline:         SnapshotHashRef{ID: "baseline", ContentHash: strings.Repeat("a", 64)},
		Current:          SnapshotHashRef{ID: "current", ContentHash: strings.Repeat("b", 64)},
		AlgorithmVersion: 1, FingerprintVersion: 1, RiskModelVersion: 1, CoveragePolicyVersion: 1,
	}
	payload, inputHash, err := HashGenerationInput(input)
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := NewQueued("tenant", "cycle", "comparison", input, payload, inputHash, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := comparison.Start(9, now); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale start error=%v", err)
	}
	if err := comparison.Start(1, now.Add(time.Second)); err != nil || comparison.Status != StatusGenerating || comparison.Attempts != 1 || comparison.Version != 2 {
		t.Fatalf("started=%+v err=%v", comparison, err)
	}
	if err := comparison.Fail("worker_timeout", true, 3, 2, now.Add(2*time.Second)); err != nil || comparison.Status != StatusQueued || comparison.Version != 3 {
		t.Fatalf("retried=%+v err=%v", comparison, err)
	}
	if err := comparison.Start(3, now.Add(3*time.Second)); err != nil || comparison.Attempts != 2 {
		t.Fatalf("restart=%+v err=%v", comparison, err)
	}
	items := []Item{
		{IdentityID: "review", CurrentObservationID: "review-current", Presence: PresenceNeedsReview},
		{IdentityID: "fixed", BaselineObservationID: "fixed-baseline", Presence: PresenceNotDetected, FixedBasis: FixedByComparableAbsence, BaselineActionable: true, ComparableBaseline: true, BaselineRiskMilli: 5000},
	}
	if err := comparison.Complete(items, 4, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if comparison.Status != StatusNeedsReview || comparison.ContentHash == "" || comparison.CompletedAt == nil || comparison.Summary.FixedCount != 1 {
		t.Fatalf("completed=%+v", comparison)
	}
	if comparison.Summary.ComparisonID != comparison.ID || comparison.Summary.BaselineSnapshotID != comparison.BaselineSnapshotID ||
		comparison.Summary.CurrentSnapshotID != comparison.CurrentSnapshotID || comparison.Summary.RiskModelVersion != comparison.RiskModelVersion {
		t.Fatalf("summary projection identity=%+v", comparison.Summary)
	}
	if comparison.Items[0].IdentityID != "fixed" || comparison.Items[1].IdentityID != "review" {
		t.Fatalf("items not sorted=%+v", comparison.Items)
	}
	if err := comparison.Supersede("successor", comparison.Version, now.Add(5*time.Second)); err != nil || comparison.Status != StatusSuperseded {
		t.Fatalf("superseded=%+v err=%v", comparison, err)
	}
}

func TestComparisonFailureDeadLettersAtAttemptLimit(t *testing.T) {
	now := time.Date(2026, 8, 31, 13, 0, 0, 0, time.UTC)
	input := GenerationInput{
		Mode:             ModeNeutral,
		Baseline:         SnapshotHashRef{ID: "a", ContentHash: strings.Repeat("a", 64)},
		Current:          SnapshotHashRef{ID: "b", ContentHash: strings.Repeat("b", 64)},
		AlgorithmVersion: 1, FingerprintVersion: 1, RiskModelVersion: 1, CoveragePolicyVersion: 1,
	}
	payload, inputHash, _ := HashGenerationInput(input)
	comparison, err := NewQueued("tenant", "cycle", "comparison", input, payload, inputHash, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := comparison.Start(1, now); err != nil {
		t.Fatal(err)
	}
	if err := comparison.Fail("classification_failed", true, 1, 2, now); err != nil {
		t.Fatal(err)
	}
	if comparison.Status != StatusFailed || comparison.FailureCode != "classification_failed" {
		t.Fatalf("failed=%+v", comparison)
	}
}

func TestComparisonOutputHashIsStable(t *testing.T) {
	now := time.Date(2026, 8, 31, 14, 0, 0, 0, time.UTC)
	input := GenerationInput{
		Mode:             ModeLifecycle,
		Baseline:         SnapshotHashRef{ID: "baseline", ContentHash: strings.Repeat("a", 64)},
		Current:          SnapshotHashRef{ID: "current", ContentHash: strings.Repeat("b", 64)},
		AlgorithmVersion: 1, FingerprintVersion: 2, RiskModelVersion: 3, CoveragePolicyVersion: 4,
	}
	payload, inputHash, err := HashGenerationInput(input)
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := NewQueued("tenant", "cycle", "comparison-golden", input, payload, inputHash, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := comparison.Start(comparison.Version, now); err != nil {
		t.Fatal(err)
	}
	items := []Item{
		{
			IdentityID: "still", BaselineObservationID: "baseline-still", CurrentObservationID: "current-still",
			Presence: PresenceDetected, ChangeFlags: []ChangeFlag{SeverityDecreased, EvidenceChanged},
			BaselineActionable: true, CurrentActionable: true, ComparableBaseline: true,
			BaselineRiskMilli: 8000, CurrentRiskMilli: 5000,
		},
		{
			IdentityID: "fixed", BaselineObservationID: "baseline-fixed", Presence: PresenceNotDetected,
			FixedBasis: FixedByComparableAbsence, BaselineActionable: true, ComparableBaseline: true,
			BaselineRiskMilli: 7000,
		},
	}
	if err := comparison.Complete(items, comparison.Version, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	const want = "040b1db08ccbaaf29b94bc095a6a4861cfa652d58cb67033a0cf907b393444e4"
	if comparison.ContentHash != want {
		t.Fatalf("content hash=%s want=%s", comparison.ContentHash, want)
	}
}

func TestComparisonCompletesOneHundredThousandItemsWithinTarget(t *testing.T) {
	now := time.Date(2026, 8, 31, 14, 0, 0, 0, time.UTC)
	input := GenerationInput{
		Mode:             ModeLifecycle,
		Baseline:         SnapshotHashRef{ID: "baseline", ContentHash: strings.Repeat("a", 64)},
		Current:          SnapshotHashRef{ID: "current", ContentHash: strings.Repeat("b", 64)},
		AlgorithmVersion: 1, FingerprintVersion: 1, RiskModelVersion: 1, CoveragePolicyVersion: 1,
	}
	payload, inputHash, err := HashGenerationInput(input)
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := NewQueued("tenant", "cycle", "comparison-scale", input, payload, inputHash, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := comparison.Start(comparison.Version, now); err != nil {
		t.Fatal(err)
	}
	items := make([]Item, 100_000)
	for index := range items {
		id := shared.ID(fmt.Sprintf("identity-%06d", index))
		items[index] = Item{
			IdentityID: id, BaselineObservationID: shared.ID("baseline-" + id), CurrentObservationID: shared.ID("current-" + id),
			Presence: PresenceDetected, ChangeFlags: []ChangeFlag{}, BaselineActionable: true, CurrentActionable: true,
			ComparableBaseline: true, BaselineRiskMilli: 5000, CurrentRiskMilli: 5000,
		}
	}
	started := time.Now()
	if err := comparison.Complete(items, comparison.Version, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Minute {
		t.Fatalf("100k comparison completion took %s", elapsed)
	}
	if len(comparison.Items) != 100_000 || comparison.Summary.BaselineCount != 100_000 || comparison.Summary.CurrentCount != 100_000 {
		t.Fatalf("scale comparison summary=%+v items=%d", comparison.Summary, len(comparison.Items))
	}
}
