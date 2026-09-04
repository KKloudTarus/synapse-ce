package memory

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type AssessmentCycleBackfillRepository struct {
	mu    sync.Mutex
	runs  map[shared.ID]map[shared.ID]ports.AssessmentCycleBackfillRun
	items map[shared.ID]map[shared.ID]map[shared.ID]ports.AssessmentCycleBackfillItem
}

func NewAssessmentCycleBackfillRepository() *AssessmentCycleBackfillRepository {
	return &AssessmentCycleBackfillRepository{
		runs:  map[shared.ID]map[shared.ID]ports.AssessmentCycleBackfillRun{},
		items: map[shared.ID]map[shared.ID]map[shared.ID]ports.AssessmentCycleBackfillItem{},
	}
}

var _ ports.AssessmentCycleBackfillStore = (*AssessmentCycleBackfillRepository)(nil)

func (repository *AssessmentCycleBackfillRepository) AcquireAssessmentCycleBackfillRun(_ context.Context, request ports.AssessmentCycleBackfillAcquireRequest) (ports.AssessmentCycleBackfillRun, bool, error) {
	if err := validateBackfillAcquire(request); err != nil {
		return ports.AssessmentCycleBackfillRun{}, false, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	tenantRuns := repository.runs[request.Run.TenantID]
	if tenantRuns == nil {
		tenantRuns = map[shared.ID]ports.AssessmentCycleBackfillRun{}
		repository.runs[request.Run.TenantID] = tenantRuns
	}
	for id, run := range tenantRuns {
		if run.State != ports.AssessmentCycleBackfillRunning {
			continue
		}
		if run.LeaseOwner != request.Run.LeaseOwner && run.LeaseExpiresAt.After(request.Run.CreatedAt) {
			return ports.AssessmentCycleBackfillRun{}, false, fmt.Errorf("%w: assessment cycle backfill already running for tenant", shared.ErrConflict)
		}
		if run.SchemaVersion != request.Run.SchemaVersion || run.DryRun != request.Run.DryRun || run.BatchSize != request.Run.BatchSize {
			return ports.AssessmentCycleBackfillRun{}, false, fmt.Errorf("%w: requested assessment cycle backfill config (schema=%d dry_run=%t batch_size=%d) differs from persisted config (schema=%d dry_run=%t batch_size=%d)", shared.ErrConflict,
				request.Run.SchemaVersion, request.Run.DryRun, request.Run.BatchSize, run.SchemaVersion, run.DryRun, run.BatchSize)
		}
		run.LeaseOwner = request.Run.LeaseOwner
		run.LeaseToken = request.Run.LeaseToken
		run.LeaseExpiresAt = request.Run.CreatedAt.Add(request.LeaseDuration)
		run.UpdatedAt = request.Run.CreatedAt
		tenantRuns[id] = run
		return cloneBackfillRun(run), true, nil
	}
	run := request.Run
	run.CheckpointAssessment = request.InitialCheckpoint
	tenantRuns[run.ID] = run
	return cloneBackfillRun(run), false, nil
}

func (repository *AssessmentCycleBackfillRepository) GetAssessmentCycleBackfillRun(_ context.Context, tenantID, runID shared.ID) (ports.AssessmentCycleBackfillRun, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	run, ok := repository.runs[shared.TenantOrDefault(tenantID)][runID]
	if !ok {
		return ports.AssessmentCycleBackfillRun{}, shared.ErrNotFound
	}
	return cloneBackfillRun(run), nil
}

func (repository *AssessmentCycleBackfillRepository) GetAssessmentCycleBackfillItem(_ context.Context, tenantID, runID, assessmentID shared.ID) (ports.AssessmentCycleBackfillItem, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	item, ok := repository.items[shared.TenantOrDefault(tenantID)][runID][assessmentID]
	if !ok {
		return ports.AssessmentCycleBackfillItem{}, shared.ErrNotFound
	}
	return item, nil
}

func (repository *AssessmentCycleBackfillRepository) CommitAssessmentCycleBackfillItem(ctx context.Context, tenantID, runID, leaseToken shared.ID, now time.Time, build func(context.Context) (ports.AssessmentCycleBackfillItem, error)) (ports.AssessmentCycleBackfillItem, bool, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	tenantID, now = shared.TenantOrDefault(tenantID), now.UTC()
	run, ok := repository.runs[tenantID][runID]
	if !ok {
		return ports.AssessmentCycleBackfillItem{}, false, shared.ErrNotFound
	}
	if run.State != ports.AssessmentCycleBackfillRunning || run.LeaseToken != leaseToken || !run.LeaseExpiresAt.After(now) {
		return ports.AssessmentCycleBackfillItem{}, false, fmt.Errorf("%w: assessment cycle backfill lease is stale", shared.ErrConflict)
	}
	item, err := build(shared.WithTenant(ctx, tenantID))
	if err != nil {
		return ports.AssessmentCycleBackfillItem{}, false, err
	}
	if item.TenantID != tenantID || item.RunID != runID {
		return ports.AssessmentCycleBackfillItem{}, false, fmt.Errorf("%w: assessment cycle backfill item ownership differs from lease", shared.ErrValidation)
	}
	if err := validateBackfillItem(item); err != nil {
		return ports.AssessmentCycleBackfillItem{}, false, err
	}
	tenantItems := repository.items[item.TenantID]
	if tenantItems == nil {
		tenantItems = map[shared.ID]map[shared.ID]ports.AssessmentCycleBackfillItem{}
		repository.items[item.TenantID] = tenantItems
	}
	runItems := tenantItems[item.RunID]
	if runItems == nil {
		runItems = map[shared.ID]ports.AssessmentCycleBackfillItem{}
		tenantItems[item.RunID] = runItems
	}
	if _, exists := runItems[item.AssessmentID]; exists {
		return item, false, nil
	}
	runItems[item.AssessmentID] = item
	return item, true, nil
}

func (repository *AssessmentCycleBackfillRepository) AdvanceAssessmentCycleBackfillRun(_ context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken, checkpoint shared.ID, now time.Time, leaseDuration time.Duration) (ports.AssessmentCycleBackfillRun, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	tenantID = shared.TenantOrDefault(tenantID)
	run, ok := repository.runs[tenantID][runID]
	if !ok {
		return ports.AssessmentCycleBackfillRun{}, shared.ErrNotFound
	}
	if run.State != ports.AssessmentCycleBackfillRunning || run.LeaseOwner != strings.TrimSpace(leaseOwner) || run.LeaseToken != leaseToken || !run.LeaseExpiresAt.After(now.UTC()) || checkpoint < run.CheckpointAssessment || leaseDuration <= 0 {
		return ports.AssessmentCycleBackfillRun{}, fmt.Errorf("%w: assessment cycle backfill checkpoint rejected", shared.ErrConflict)
	}
	run.CheckpointAssessment, run.UpdatedAt, run.LeaseExpiresAt = checkpoint, now.UTC(), now.UTC().Add(leaseDuration)
	recomputeBackfillCounts(&run, repository.items[tenantID][runID])
	repository.runs[tenantID][runID] = run
	return cloneBackfillRun(run), nil
}

func (repository *AssessmentCycleBackfillRepository) FinishAssessmentCycleBackfillRun(_ context.Context, tenantID, runID shared.ID, leaseOwner string, leaseToken shared.ID, state ports.AssessmentCycleBackfillState, now time.Time) (ports.AssessmentCycleBackfillRun, error) {
	if state != ports.AssessmentCycleBackfillCompleted && state != ports.AssessmentCycleBackfillCancelled && state != ports.AssessmentCycleBackfillFailed {
		return ports.AssessmentCycleBackfillRun{}, fmt.Errorf("%w: invalid assessment cycle backfill terminal state", shared.ErrValidation)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	tenantID = shared.TenantOrDefault(tenantID)
	run, ok := repository.runs[tenantID][runID]
	if !ok {
		return ports.AssessmentCycleBackfillRun{}, shared.ErrNotFound
	}
	if run.State != ports.AssessmentCycleBackfillRunning || run.LeaseOwner != strings.TrimSpace(leaseOwner) || run.LeaseToken != leaseToken || !run.LeaseExpiresAt.After(now.UTC()) {
		return ports.AssessmentCycleBackfillRun{}, fmt.Errorf("%w: assessment cycle backfill completion rejected", shared.ErrConflict)
	}
	completedAt := now.UTC()
	run.State, run.UpdatedAt, run.CompletedAt = state, completedAt, &completedAt
	run.LeaseOwner, run.LeaseToken, run.LeaseExpiresAt = "", "", time.Time{}
	recomputeBackfillCounts(&run, repository.items[tenantID][runID])
	repository.runs[tenantID][runID] = run
	return cloneBackfillRun(run), nil
}

func validateBackfillAcquire(request ports.AssessmentCycleBackfillAcquireRequest) error {
	run := request.Run
	if run.TenantID.IsZero() || run.ID.IsZero() || run.LeaseToken.IsZero() || run.SchemaVersion <= 0 || run.BatchSize < 1 || run.BatchSize > 2000 || run.SnapshotAt.IsZero() || run.State != ports.AssessmentCycleBackfillRunning || strings.TrimSpace(run.LeaseOwner) == "" || len(run.LeaseOwner) > 256 || run.LeaseExpiresAt.IsZero() || strings.TrimSpace(run.CreatedBy) == "" || len(run.CreatedBy) > 256 || run.CreatedAt.IsZero() || request.LeaseDuration <= 0 {
		return fmt.Errorf("%w: assessment cycle backfill run is invalid", shared.ErrValidation)
	}
	return nil
}

func validateBackfillItem(item ports.AssessmentCycleBackfillItem) error {
	validOutcome := item.Outcome == "created" || item.Outcome == "would_create" || item.Outcome == "skipped" || item.Outcome == "failed"
	if item.TenantID.IsZero() || item.RunID.IsZero() || item.AssessmentID.IsZero() || item.SchemaVersion <= 0 || strings.TrimSpace(item.IdempotencyKey) == "" || len(item.IdempotencyKey) > 128 || !validOutcome || strings.TrimSpace(item.ReasonCode) == "" || len(item.ReasonCode) > 64 || len(item.RepairGuidance) > 1024 || item.ProcessedAt.IsZero() {
		return fmt.Errorf("%w: assessment cycle backfill item is invalid", shared.ErrValidation)
	}
	return nil
}

func recomputeBackfillCounts(run *ports.AssessmentCycleBackfillRun, items map[shared.ID]ports.AssessmentCycleBackfillItem) {
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

func cloneBackfillRun(run ports.AssessmentCycleBackfillRun) ports.AssessmentCycleBackfillRun {
	if run.CompletedAt != nil {
		completedAt := *run.CompletedAt
		run.CompletedAt = &completedAt
	}
	return run
}
