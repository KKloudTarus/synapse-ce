package memory

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type AssessmentComparisonRepository struct {
	mu          sync.RWMutex
	comparisons map[comparisonKey]assessmentcomparison.Comparison
	byInputHash map[string]comparisonKey
}

type comparisonKey struct {
	tenantID shared.ID
	cycleID  shared.ID
	id       shared.ID
}

func NewAssessmentComparisonRepository() *AssessmentComparisonRepository {
	return &AssessmentComparisonRepository{
		comparisons: map[comparisonKey]assessmentcomparison.Comparison{},
		byInputHash: map[string]comparisonKey{},
	}
}

var _ ports.AssessmentComparisonRepository = (*AssessmentComparisonRepository)(nil)

func (repository *AssessmentComparisonRepository) CreateQueued(ctx context.Context, comparison assessmentcomparison.Comparison) (assessmentcomparison.Comparison, bool, error) {
	if err := ctx.Err(); err != nil {
		return assessmentcomparison.Comparison{}, false, err
	}
	comparison.TenantID = shared.TenantOrDefault(comparison.TenantID)
	if err := comparison.Validate(); err != nil {
		return assessmentcomparison.Comparison{}, false, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	hashKey := comparison.TenantID.String() + "\x00" + comparison.InputHash
	if existingKey, exists := repository.byInputHash[hashKey]; exists {
		existing := repository.comparisons[existingKey]
		if !sameComparisonRequest(existing, comparison) {
			return assessmentcomparison.Comparison{}, false, fmt.Errorf("%w: comparison input hash was reused with different content", shared.ErrConflict)
		}
		return cloneAssessmentComparison(existing), false, nil
	}
	key := comparisonKey{tenantID: comparison.TenantID, cycleID: comparison.CycleID, id: comparison.ID}
	if _, exists := repository.comparisons[key]; exists {
		return assessmentcomparison.Comparison{}, false, fmt.Errorf("%w: comparison id was reused", shared.ErrConflict)
	}
	repository.comparisons[key] = cloneAssessmentComparison(comparison)
	repository.byInputHash[hashKey] = key
	return cloneAssessmentComparison(comparison), true, nil
}

func (repository *AssessmentComparisonRepository) Get(ctx context.Context, tenantID, comparisonID shared.ID) (assessmentcomparison.Comparison, error) {
	if err := ctx.Err(); err != nil {
		return assessmentcomparison.Comparison{}, err
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	for key, comparison := range repository.comparisons {
		if key.tenantID == tenantID && key.id == comparisonID {
			return cloneAssessmentComparison(comparison), nil
		}
	}
	return assessmentcomparison.Comparison{}, shared.ErrNotFound
}

func (repository *AssessmentComparisonRepository) GetMetadata(ctx context.Context, tenantID, comparisonID shared.ID) (assessmentcomparison.Comparison, error) {
	comparison, err := repository.Get(ctx, tenantID, comparisonID)
	comparison.Items = nil
	return comparison, err
}

func (repository *AssessmentComparisonRepository) GetByInputHash(ctx context.Context, tenantID shared.ID, inputHash string) (assessmentcomparison.Comparison, error) {
	if err := ctx.Err(); err != nil {
		return assessmentcomparison.Comparison{}, err
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	key, exists := repository.byInputHash[tenantID.String()+"\x00"+inputHash]
	if !exists {
		return assessmentcomparison.Comparison{}, shared.ErrNotFound
	}
	return cloneAssessmentComparison(repository.comparisons[key]), nil
}

func (repository *AssessmentComparisonRepository) ListMetadataByCycle(ctx context.Context, tenantID, cycleID shared.ID) ([]assessmentcomparison.Comparison, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	result := make([]assessmentcomparison.Comparison, 0)
	for key, comparison := range repository.comparisons {
		if key.tenantID != tenantID || comparison.CycleID != cycleID {
			continue
		}
		value := cloneAssessmentComparison(comparison)
		value.Items = nil
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].CreatedAt.Equal(result[right].CreatedAt) {
			return result[left].ID < result[right].ID
		}
		return result[left].CreatedAt.Before(result[right].CreatedAt)
	})
	return result, nil
}

func (repository *AssessmentComparisonRepository) GetAssessmentComparisonBacklog(ctx context.Context, tenantID shared.ID) (ports.AssessmentComparisonBacklog, error) {
	if err := ctx.Err(); err != nil {
		return ports.AssessmentComparisonBacklog{}, err
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	var backlog ports.AssessmentComparisonBacklog
	for key, comparison := range repository.comparisons {
		if key.tenantID != tenantID {
			continue
		}
		switch comparison.Status {
		case assessmentcomparison.StatusQueued:
			backlog.Queued++
			setOldestAssessmentComparison(&backlog, comparison.CreatedAt)
		case assessmentcomparison.StatusGenerating:
			backlog.Generating++
			setOldestAssessmentComparison(&backlog, comparison.UpdatedAt)
		case assessmentcomparison.StatusFailed:
			backlog.Failed++
			if comparison.FailureCode == "dead_lettered" {
				backlog.DeadLettered++
			}
		}
	}
	return backlog, nil
}

func (repository *AssessmentComparisonRepository) ListFailedAssessmentComparisons(ctx context.Context, tenantID shared.ID, limit int) ([]assessmentcomparison.Comparison, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 2000 {
		return nil, fmt.Errorf("%w: failed comparison limit must be between 1 and 2000", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	result := make([]assessmentcomparison.Comparison, 0)
	for key, comparison := range repository.comparisons {
		if key.tenantID == tenantID && comparison.Status == assessmentcomparison.StatusFailed {
			comparison.Items = nil
			result = append(result, cloneAssessmentComparison(comparison))
		}
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].UpdatedAt.Equal(result[right].UpdatedAt) {
			return result[left].ID < result[right].ID
		}
		return result[left].UpdatedAt.Before(result[right].UpdatedAt)
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (repository *AssessmentComparisonRepository) GetItem(ctx context.Context, tenantID, comparisonID, itemID shared.ID) (assessmentcomparison.Item, error) {
	comparison, err := repository.Get(ctx, tenantID, comparisonID)
	if err != nil {
		return assessmentcomparison.Item{}, err
	}
	for _, item := range comparison.Items {
		if item.ID == itemID {
			return cloneAssessmentComparisonItem(item), nil
		}
	}
	return assessmentcomparison.Item{}, shared.ErrNotFound
}

func (repository *AssessmentComparisonRepository) ListItems(ctx context.Context, tenantID, comparisonID shared.ID, filter ports.AssessmentComparisonItemFilter) (ports.AssessmentComparisonItemPage, error) {
	comparison, err := repository.Get(ctx, tenantID, comparisonID)
	if err != nil {
		return ports.AssessmentComparisonItemPage{}, err
	}
	items := make([]assessmentcomparison.Item, 0, filter.Limit)
	for _, item := range comparison.Items {
		severity := item.CurrentObservation.Severity
		if item.CurrentObservationID.IsZero() {
			severity = item.BaselineObservation.Severity
		}
		if item.Position <= filter.AfterPosition || filter.Presence != "" && filter.Presence != string(item.Presence) && filter.Presence != string(item.NeutralPresence) ||
			filter.ChangeFlag != "" && !comparisonItemHasFlag(item, filter.ChangeFlag) || filter.Severity != "" && filter.Severity != severity ||
			filter.ProducerKind != "" && filter.ProducerKind != item.ProducerKind || filter.FindingKind != "" && filter.FindingKind != item.FindingKind ||
			filter.Disposition != "" && filter.Disposition != comparisonItemDisposition(item) || filter.ReviewState != "" && filter.ReviewState != comparisonItemReviewState(item) {
			continue
		}
		if len(items) == filter.Limit {
			return ports.AssessmentComparisonItemPage{Items: items, NextPosition: items[len(items)-1].Position, HasMore: true}, nil
		}
		items = append(items, cloneAssessmentComparisonItem(item))
	}
	next := filter.AfterPosition
	if len(items) > 0 {
		next = items[len(items)-1].Position
	}
	return ports.AssessmentComparisonItemPage{Items: items, NextPosition: next}, nil
}

func (repository *AssessmentComparisonRepository) UpdateCAS(ctx context.Context, comparison assessmentcomparison.Comparison, expectedVersion int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	comparison.TenantID = shared.TenantOrDefault(comparison.TenantID)
	if err := comparison.Validate(); err != nil {
		return err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := comparisonKey{tenantID: comparison.TenantID, cycleID: comparison.CycleID, id: comparison.ID}
	existing, exists := repository.comparisons[key]
	if !exists {
		return shared.ErrNotFound
	}
	if existing.Version != expectedVersion || comparison.Version != expectedVersion+1 {
		return fmt.Errorf("%w: comparison version mismatch", shared.ErrConflict)
	}
	if !sameComparisonImmutable(existing, comparison) || !validComparisonTransition(existing.Status, comparison.Status) || terminalComparisonChanged(existing, comparison) {
		return fmt.Errorf("%w: immutable comparison input or output changed", shared.ErrConflict)
	}
	repository.comparisons[key] = cloneAssessmentComparison(comparison)
	return nil
}

func sameComparisonRequest(left, right assessmentcomparison.Comparison) bool {
	return left.TenantID == right.TenantID && left.CycleID == right.CycleID &&
		left.BaselineSnapshotID == right.BaselineSnapshotID && left.CurrentSnapshotID == right.CurrentSnapshotID &&
		left.Mode == right.Mode && left.InputHash == right.InputHash && reflect.DeepEqual(left.InputPayload, right.InputPayload) &&
		left.AlgorithmVersion == right.AlgorithmVersion && left.FingerprintVersion == right.FingerprintVersion &&
		left.RiskModelVersion == right.RiskModelVersion && left.CoveragePolicyVersion == right.CoveragePolicyVersion
}

func sameComparisonImmutable(left, right assessmentcomparison.Comparison) bool {
	return sameComparisonRequest(left, right) && left.ID == right.ID && left.CreatedAt.Equal(right.CreatedAt)
}

func validComparisonTransition(from, to assessmentcomparison.Status) bool {
	switch from {
	case assessmentcomparison.StatusQueued:
		return to == assessmentcomparison.StatusGenerating
	case assessmentcomparison.StatusGenerating:
		return to == assessmentcomparison.StatusQueued || to == assessmentcomparison.StatusComplete || to == assessmentcomparison.StatusNeedsReview || to == assessmentcomparison.StatusFailed
	case assessmentcomparison.StatusFailed:
		return to == assessmentcomparison.StatusGenerating
	case assessmentcomparison.StatusComplete, assessmentcomparison.StatusNeedsReview:
		return to == assessmentcomparison.StatusSuperseded
	}
	return false
}

func terminalComparisonChanged(existing, updated assessmentcomparison.Comparison) bool {
	if existing.Status != assessmentcomparison.StatusComplete && existing.Status != assessmentcomparison.StatusNeedsReview && existing.Status != assessmentcomparison.StatusSuperseded {
		return false
	}
	return existing.ContentHash != updated.ContentHash || !reflect.DeepEqual(existing.Items, updated.Items) || !reflect.DeepEqual(existing.Summary, updated.Summary) ||
		!sameTime(existing.CompletedAt, updated.CompletedAt)
}

func cloneAssessmentComparison(comparison assessmentcomparison.Comparison) assessmentcomparison.Comparison {
	comparison.InputPayload = append([]byte(nil), comparison.InputPayload...)
	comparison.Items = append([]assessmentcomparison.Item(nil), comparison.Items...)
	for index := range comparison.Items {
		comparison.Items[index] = cloneAssessmentComparisonItem(comparison.Items[index])
	}
	if comparison.CompletedAt != nil {
		value := *comparison.CompletedAt
		comparison.CompletedAt = &value
	}
	if comparison.SupersededAt != nil {
		value := *comparison.SupersededAt
		comparison.SupersededAt = &value
	}
	return comparison
}

func setOldestAssessmentComparison(backlog *ports.AssessmentComparisonBacklog, candidate time.Time) {
	if candidate.IsZero() || backlog.OldestActiveAt != nil && !candidate.Before(*backlog.OldestActiveAt) {
		return
	}
	oldest := candidate.UTC()
	backlog.OldestActiveAt = &oldest
}

func cloneAssessmentComparisonItem(item assessmentcomparison.Item) assessmentcomparison.Item {
	item.ChangeFlags = append([]assessmentcomparison.ChangeFlag(nil), item.ChangeFlags...)
	item.ReviewCandidateIDs = append([]shared.ID(nil), item.ReviewCandidateIDs...)
	item.MatchMethods = append([]findinglineage.MatchMethod(nil), item.MatchMethods...)
	return item
}

func comparisonItemDisposition(item assessmentcomparison.Item) string {
	if item.CurrentActionable {
		return "current_actionable"
	}
	if item.BaselineActionable {
		return "baseline_only"
	}
	return "non_actionable"
}

func comparisonItemReviewState(item assessmentcomparison.Item) string {
	if item.Presence == assessmentcomparison.PresenceNeedsReview || item.NeutralPresence == assessmentcomparison.NeutralNeedsReview || len(item.ReviewCandidateIDs) > 0 {
		return "needs_review"
	}
	if !item.VerificationID.IsZero() {
		return "verified"
	}
	return "clear"
}

func comparisonItemHasFlag(item assessmentcomparison.Item, flag assessmentcomparison.ChangeFlag) bool {
	for _, candidate := range item.ChangeFlags {
		if candidate == flag {
			return true
		}
	}
	return false
}

func sameTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}
