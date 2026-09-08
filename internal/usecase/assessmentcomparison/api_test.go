package assessmentcomparison

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	lineageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findinglineage"
)

func TestComparisonAPIIdempotencyPaginationAndReviewReplacement(t *testing.T) {
	harness := newComparisonHarness(t)
	ctx := context.Background()
	targetIdentity, targetObservation := comparisonLineagePair(t, harness, "review-target", harness.snapshotsByNumber[3].ID, "review-target-observation", shared.SeverityMedium, 2100, harness.clock.Now())
	createIdentity(t, harness.lineage, targetIdentity, targetObservation)
	sourceIdentity, sourceObservation := comparisonLineagePair(t, harness, "review-source", harness.snapshotsByNumber[3].ID, "review-source-observation", shared.SeverityMedium, 2200, harness.clock.Now())
	createIdentity(t, harness.lineage, sourceIdentity, sourceObservation)
	candidate, err := findinglineage.NewMatchCandidate(findinglineage.MatchCandidate{
		TenantID: harness.tenantID, CycleID: harness.cycleID, SnapshotID: harness.snapshotsByNumber[3].ID, ID: "review-candidate",
		ProducerKind: "sca", FindingKind: "vulnerability", Reason: findinglineage.ReasonMerge, FingerprintSchemaVersion: 1,
		Fingerprint: strings.Repeat("d", 64), SourceReferenceHash: strings.Repeat("c", 64), CreatedAt: harness.clock.Now(),
		Refs: []findinglineage.CandidateRef{
			{Position: 0, Role: findinglineage.RoleSource, ObservationID: sourceObservation.ID, Method: findinglineage.MethodMatcher, ScoreMilli: 1000, Confidence: findinglineage.ConfidenceHigh},
			{Position: 1, Role: findinglineage.RoleCandidate, IdentityID: targetIdentity.ID, Method: findinglineage.MethodFingerprint, ScoreMilli: 900, Confidence: findinglineage.ConfidenceHigh},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := harness.lineage.CreateCandidate(ctx, candidate, ""); err != nil || !created {
		t.Fatalf("candidate created=%v err=%v", created, err)
	}
	lineageService, err := lineageuc.NewService(harness.lineage, harness.service.transactions, harness.audit, harness.clock, &comparisonIDs{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	requests := memory.NewAssessmentCycleRequestRepository()
	queue := memory.NewJobQueue(&comparisonIDs{}, harness.clock.Now)
	harness.service.SetAPIStores(requests, queue, lineageService)

	request := RetainedRequest{TenantID: harness.tenantID, Actor: "operator", Route: "POST /api/v1/assessment-comparisons", IdempotencyKey: "comparison-create"}
	queuedResponse, err := harness.service.QueueRetained(ctx, request, QueueInput{
		BaselineSnapshotID: harness.snapshotsByNumber[2].ID, CurrentSnapshotID: harness.snapshotsByNumber[3].ID,
		Mode: domain.ModeLifecycle, FingerprintVersion: 1, RiskModelVersion: 1,
	})
	if err != nil || queuedResponse.StatusCode != 202 {
		t.Fatalf("queue status=%d err=%v body=%s", queuedResponse.StatusCode, err, queuedResponse.Body)
	}
	var queued QueueResult
	if err := json.Unmarshal(queuedResponse.Body, &queued); err != nil || queued.Comparison.ID.IsZero() || !queued.Created {
		t.Fatalf("queued=%+v err=%v", queued, err)
	}
	replay, err := harness.service.QueueRetained(ctx, request, QueueInput{
		BaselineSnapshotID: harness.snapshotsByNumber[2].ID, CurrentSnapshotID: harness.snapshotsByNumber[3].ID,
		Mode: domain.ModeLifecycle, FingerprintVersion: 1, RiskModelVersion: 1,
	})
	if err != nil || !replay.Replayed || string(replay.Body) != string(queuedResponse.Body) {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	_, err = harness.service.QueueRetained(ctx, request, QueueInput{
		BaselineSnapshotID: harness.snapshotsByNumber[1].ID, CurrentSnapshotID: harness.snapshotsByNumber[3].ID,
		Mode: domain.ModeLifecycle, FingerprintVersion: 1, RiskModelVersion: 1,
	})
	if !errors.Is(err, shared.ErrConflict) || ErrorCode(err) != CodeIdempotencyBodyMismatch {
		t.Fatalf("body mismatch error=%v code=%s", err, ErrorCode(err))
	}

	completed, err := harness.service.Generate(ctx, WorkInput{TenantID: harness.tenantID, ComparisonID: queued.Comparison.ID, Actor: "worker"})
	if err != nil || completed.Status != domain.StatusNeedsReview {
		t.Fatalf("completed=%+v err=%v", completed, err)
	}
	firstPage, err := harness.service.ListItems(ctx, ListItemsInput{TenantID: harness.tenantID, ComparisonID: completed.ID, Limit: 2})
	if err != nil || len(firstPage.Items) != 2 || firstPage.NextCursor == "" {
		t.Fatalf("first page=%+v err=%v", firstPage, err)
	}
	secondPage, err := harness.service.ListItems(ctx, ListItemsInput{TenantID: harness.tenantID, ComparisonID: completed.ID, Limit: 2, Cursor: firstPage.NextCursor})
	if err != nil || len(secondPage.Items) == 0 || firstPage.Items[1].ID == secondPage.Items[0].ID {
		t.Fatalf("second page=%+v err=%v", secondPage, err)
	}

	targetItem := comparisonItem(t, completed, targetIdentity.ID)
	if !containsID(targetItem.ReviewCandidateIDs, candidate.ID) {
		t.Fatalf("target review candidates=%v", targetItem.ReviewCandidateIDs)
	}
	if len(targetItem.ReviewCandidates) != 1 || targetItem.ReviewCandidates[0].ID != candidate.ID || !containsID(targetItem.ReviewCandidates[0].SourceObservationIDs, sourceObservation.ID) {
		t.Fatalf("target review candidate metadata=%+v", targetItem.ReviewCandidates)
	}
	reviewRequest := RetainedRequest{TenantID: harness.tenantID, Actor: "reviewer", Route: "POST /api/v1/assessment-comparisons/{comparisonId}/items/{itemId}/confirm", IdempotencyKey: "review-confirm"}
	reviewResponse, err := harness.service.Review(ctx, ReviewInput{
		Request: reviewRequest, ComparisonID: completed.ID, ItemID: targetItem.ID, CandidateID: candidate.ID,
		SourceObservationID: sourceObservation.ID, ExpectedVersion: completed.Version, Action: ReviewConfirm, Reason: "confirmed deterministic lineage",
	})
	if err != nil || reviewResponse.StatusCode != 202 {
		t.Fatalf("review status=%d err=%v body=%s", reviewResponse.StatusCode, err, reviewResponse.Body)
	}
	var review ReviewResult
	if err := json.Unmarshal(reviewResponse.Body, &review); err != nil || review.OverrideEventID.IsZero() || review.SupersededComparisonID != completed.ID || review.ReplacementComparisonID.IsZero() || review.ReplacementComparisonID == completed.ID {
		t.Fatalf("review=%+v err=%v", review, err)
	}
	reviewReplay, err := harness.service.Review(ctx, ReviewInput{
		Request: reviewRequest, ComparisonID: completed.ID, ItemID: targetItem.ID, CandidateID: candidate.ID,
		SourceObservationID: sourceObservation.ID, ExpectedVersion: completed.Version, Action: ReviewConfirm, Reason: "confirmed deterministic lineage",
	})
	if err != nil || !reviewReplay.Replayed || string(reviewReplay.Body) != string(reviewResponse.Body) {
		t.Fatalf("review replay=%+v err=%v", reviewReplay, err)
	}
	old, err := harness.comparisons.Get(ctx, harness.tenantID, completed.ID)
	if err != nil || old.Status != domain.StatusSuperseded || old.SupersededBy != review.ReplacementComparisonID {
		t.Fatalf("old comparison=%+v err=%v", old, err)
	}
	active, err := harness.lineage.GetActiveOverride(ctx, harness.tenantID, harness.cycleID, sourceObservation.ID)
	if err != nil || active.Action != findinglineage.OverrideConfirm || active.TargetIdentityID != targetIdentity.ID {
		t.Fatalf("active override=%+v err=%v", active, err)
	}
}

func TestComparisonItemTokenFilterAcceptsCanonicalProducerNames(t *testing.T) {
	for _, value := range []string{"", "semgrep.sast", "vendor-scanner_v2"} {
		if !validItemTokenFilter(value) {
			t.Fatalf("expected valid item token filter %q", value)
		}
	}
	for _, value := range []string{" leading", "line\nbreak", strings.Repeat("x", 257)} {
		if validItemTokenFilter(value) {
			t.Fatalf("expected invalid item token filter %q", value)
		}
	}
}
