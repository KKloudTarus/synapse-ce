package memory

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type AssessmentSnapshotBackfillRepository struct {
	mu    sync.Mutex
	runs  map[shared.ID]map[shared.ID]ports.AssessmentSnapshotBackfillRun
	items map[shared.ID]map[shared.ID]map[shared.ID]ports.AssessmentSnapshotBackfillItem
}

func NewAssessmentSnapshotBackfillRepository() *AssessmentSnapshotBackfillRepository {
	return &AssessmentSnapshotBackfillRepository{
		runs:  map[shared.ID]map[shared.ID]ports.AssessmentSnapshotBackfillRun{},
		items: map[shared.ID]map[shared.ID]map[shared.ID]ports.AssessmentSnapshotBackfillItem{},
	}
}

var _ ports.AssessmentSnapshotBackfillStore = (*AssessmentSnapshotBackfillRepository)(nil)

func (repository *AssessmentSnapshotBackfillRepository) AcquireAssessmentSnapshotBackfillRun(_ context.Context, request ports.AssessmentSnapshotBackfillAcquireRequest) (ports.AssessmentSnapshotBackfillRun, bool, error) {
	if err := validateAssessmentSnapshotBackfillAcquire(request); err != nil {
		return ports.AssessmentSnapshotBackfillRun{}, false, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	tenantRuns := repository.runs[request.Run.TenantID]
	if tenantRuns == nil {
		tenantRuns = map[shared.ID]ports.AssessmentSnapshotBackfillRun{}
		repository.runs[request.Run.TenantID] = tenantRuns
	}
	for id, run := range tenantRuns {
		if run.State != ports.AssessmentSnapshotBackfillRunning {
			continue
		}
		if run.LeaseOwner != request.Run.LeaseOwner && run.LeaseExpiresAt.After(request.Run.CreatedAt) {
			return ports.AssessmentSnapshotBackfillRun{}, false, fmt.Errorf("%w: assessment snapshot backfill already running for tenant", shared.ErrConflict)
		}
		if run.SchemaVersion != request.Run.SchemaVersion || run.DryRun != request.Run.DryRun || run.BatchSize != request.Run.BatchSize {
			return ports.AssessmentSnapshotBackfillRun{}, false, fmt.Errorf("%w: requested assessment snapshot backfill config (schema=%d dry_run=%t batch_size=%d) differs from persisted config (schema=%d dry_run=%t batch_size=%d)", shared.ErrConflict,
				request.Run.SchemaVersion, request.Run.DryRun, request.Run.BatchSize, run.SchemaVersion, run.DryRun, run.BatchSize)
		}
		run.LeaseOwner = request.Run.LeaseOwner
		run.LeaseToken = request.Run.LeaseToken
		run.LeaseExpiresAt = request.Run.CreatedAt.Add(request.LeaseDuration)
		run.UpdatedAt = request.Run.CreatedAt
		tenantRuns[id] = run
		return cloneAssessmentSnapshotBackfillRun(run), true, nil
	}
	run := request.Run
	run.CheckpointAssessment = request.InitialCheckpoint
	run.LeaseExpiresAt = run.CreatedAt.Add(request.LeaseDuration)
	tenantRuns[run.ID] = run
	return cloneAssessmentSnapshotBackfillRun(run), false, nil
}

func (repository *AssessmentSnapshotBackfillRepository) GetAssessmentSnapshotBackfillRun(_ context.Context, tenantID, runID shared.ID) (ports.AssessmentSnapshotBackfillRun, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	tenantID = shared.TenantOrDefault(tenantID)
	run, ok := repository.runs[tenantID][runID]
	if !ok {
		return ports.AssessmentSnapshotBackfillRun{}, shared.ErrNotFound
	}
	return cloneAssessmentSnapshotBackfillRun(run), nil
}

func (repository *AssessmentSnapshotBackfillRepository) GetAssessmentSnapshotBackfillItem(_ context.Context, tenantID, runID, assessmentID shared.ID) (ports.AssessmentSnapshotBackfillItem, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	tenantID = shared.TenantOrDefault(tenantID)
	item, ok := repository.items[tenantID][runID][assessmentID]
	if !ok {
		return ports.AssessmentSnapshotBackfillItem{}, shared.ErrNotFound
	}
	return item, nil
}

func (repository *AssessmentSnapshotBackfillRepository) CommitAssessmentSnapshotBackfillItem(ctx context.Context, tenantID, runID, leaseToken shared.ID, now time.Time, build func(context.Context) (ports.AssessmentSnapshotBackfillItem, error)) (ports.AssessmentSnapshotBackfillItem, bool, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	tenantID, now = shared.TenantOrDefault(tenantID), now.UTC()
	run, ok := repository.runs[tenantID][runID]
	if !ok {
		return ports.AssessmentSnapshotBackfillItem{}, false, shared.ErrNotFound
	}
	if run.State != ports.AssessmentSnapshotBackfillRunning || run.LeaseToken != leaseToken || !run.LeaseExpiresAt.After(now) {
		return ports.AssessmentSnapshotBackfillItem{}, false, fmt.Errorf("%w: assessment snapshot backfill lease is stale", shared.ErrConflict)
	}
	item, err := build(shared.WithTenant(ctx, tenantID))
	if err != nil {
		return ports.AssessmentSnapshotBackfillItem{}, false, err
	}
	if item.TenantID != tenantID || item.RunID != runID {
		return ports.AssessmentSnapshotBackfillItem{}, false, fmt.Errorf("%w: assessment snapshot backfill item ownership differs from lease", shared.ErrValidation)
	}
	if err := validateAssessmentSnapshotBackfillItem(item); err != nil {
		return ports.AssessmentSnapshotBackfillItem{}, false, err
	}
	tenantItems := repository.items[item.TenantID]
	if tenantItems == nil {
		tenantItems = map[shared.ID]map[shared.ID]ports.AssessmentSnapshotBackfillItem{}
		repository.items[item.TenantID] = tenantItems
	}
	runItems := tenantItems[item.RunID]
	if runItems == nil {
		runItems = map[shared.ID]ports.AssessmentSnapshotBackfillItem{}
		tenantItems[item.RunID] = runItems
	}
	if _, exists := runItems[item.AssessmentID]; exists {
		return item, false, nil
	}
	runItems[item.AssessmentID] = item
	return item, true, nil
}

func (repository *AssessmentSnapshotBackfillRepository) AdvanceAssessmentSnapshotBackfillRun(_ context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken, checkpoint shared.ID, now time.Time, leaseDuration time.Duration) (ports.AssessmentSnapshotBackfillRun, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	tenantID = shared.TenantOrDefault(tenantID)
	run, ok := repository.runs[tenantID][runID]
	if !ok {
		return ports.AssessmentSnapshotBackfillRun{}, shared.ErrNotFound
	}
	if run.State != ports.AssessmentSnapshotBackfillRunning || run.LeaseOwner != strings.TrimSpace(leaseOwner) || run.LeaseToken != leaseToken || !run.LeaseExpiresAt.After(now.UTC()) || checkpoint < run.CheckpointAssessment || leaseDuration <= 0 {
		return ports.AssessmentSnapshotBackfillRun{}, fmt.Errorf("%w: assessment snapshot backfill checkpoint rejected", shared.ErrConflict)
	}
	run.CheckpointAssessment, run.UpdatedAt, run.LeaseExpiresAt = checkpoint, now.UTC(), now.UTC().Add(leaseDuration)
	recomputeAssessmentSnapshotBackfillCounts(&run, repository.items[tenantID][runID])
	repository.runs[tenantID][runID] = run
	return cloneAssessmentSnapshotBackfillRun(run), nil
}

func (repository *AssessmentSnapshotBackfillRepository) FinishAssessmentSnapshotBackfillRun(_ context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken shared.ID, state ports.AssessmentSnapshotBackfillState, now time.Time) (ports.AssessmentSnapshotBackfillRun, error) {
	if state != ports.AssessmentSnapshotBackfillCompleted && state != ports.AssessmentSnapshotBackfillCancelled && state != ports.AssessmentSnapshotBackfillFailed {
		return ports.AssessmentSnapshotBackfillRun{}, fmt.Errorf("%w: invalid assessment snapshot backfill terminal state", shared.ErrValidation)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	tenantID = shared.TenantOrDefault(tenantID)
	run, ok := repository.runs[tenantID][runID]
	if !ok {
		return ports.AssessmentSnapshotBackfillRun{}, shared.ErrNotFound
	}
	if run.State != ports.AssessmentSnapshotBackfillRunning || run.LeaseOwner != strings.TrimSpace(leaseOwner) || run.LeaseToken != leaseToken || !run.LeaseExpiresAt.After(now.UTC()) {
		return ports.AssessmentSnapshotBackfillRun{}, fmt.Errorf("%w: assessment snapshot backfill completion rejected", shared.ErrConflict)
	}
	completedAt := now.UTC()
	run.State, run.UpdatedAt, run.CompletedAt = state, completedAt, &completedAt
	run.LeaseOwner, run.LeaseToken, run.LeaseExpiresAt = "", "", time.Time{}
	recomputeAssessmentSnapshotBackfillCounts(&run, repository.items[tenantID][runID])
	repository.runs[tenantID][runID] = run
	return cloneAssessmentSnapshotBackfillRun(run), nil
}

func validateAssessmentSnapshotBackfillAcquire(request ports.AssessmentSnapshotBackfillAcquireRequest) error {
	run := request.Run
	if run.TenantID.IsZero() || run.ID.IsZero() || run.LeaseToken.IsZero() || run.SchemaVersion <= 0 || run.BatchSize < 1 || run.BatchSize > 2000 || run.SnapshotAt.IsZero() || run.State != ports.AssessmentSnapshotBackfillRunning || strings.TrimSpace(run.LeaseOwner) == "" || len(run.LeaseOwner) > 256 || run.LeaseExpiresAt.IsZero() || strings.TrimSpace(run.CreatedBy) == "" || len(run.CreatedBy) > 256 || run.CreatedAt.IsZero() || request.LeaseDuration <= 0 {
		return fmt.Errorf("%w: assessment snapshot backfill run is invalid", shared.ErrValidation)
	}
	return nil
}

func validateAssessmentSnapshotBackfillItem(item ports.AssessmentSnapshotBackfillItem) error {
	validOutcome := item.Outcome == "created" || item.Outcome == "would_create" || item.Outcome == "skipped" || item.Outcome == "failed"
	_, hashErr := hex.DecodeString(item.SourceHash)
	if item.TenantID.IsZero() || item.RunID.IsZero() || item.AssessmentID.IsZero() || item.SchemaVersion <= 0 || strings.TrimSpace(item.IdempotencyKey) == "" || len(item.IdempotencyKey) > 128 || len(item.SourceHash) != 64 || strings.ToLower(item.SourceHash) != item.SourceHash || hashErr != nil || !validOutcome || strings.TrimSpace(item.ReasonCode) == "" || len(item.ReasonCode) > 64 || len(item.RepairGuidance) > 1024 || item.ProcessedAt.IsZero() {
		return fmt.Errorf("%w: assessment snapshot backfill item is invalid", shared.ErrValidation)
	}
	if item.Outcome == "created" && item.SnapshotID.IsZero() {
		return fmt.Errorf("%w: created assessment snapshot backfill item requires a snapshot", shared.ErrValidation)
	}
	return nil
}

func recomputeAssessmentSnapshotBackfillCounts(run *ports.AssessmentSnapshotBackfillRun, items map[shared.ID]ports.AssessmentSnapshotBackfillItem) {
	run.ProcessedCount, run.CreatedCount, run.WouldCreateCount, run.SkippedCount, run.FailedCount = 0, 0, 0, 0, 0
	for _, item := range items {
		run.ProcessedCount++
		switch item.Outcome {
		case "created":
			run.CreatedCount++
		case "would_create":
			run.WouldCreateCount++
		case "skipped":
			run.SkippedCount++
		case "failed":
			run.FailedCount++
		}
	}
}

func cloneAssessmentSnapshotBackfillRun(run ports.AssessmentSnapshotBackfillRun) ports.AssessmentSnapshotBackfillRun {
	if run.CompletedAt != nil {
		completedAt := *run.CompletedAt
		run.CompletedAt = &completedAt
	}
	return run
}
