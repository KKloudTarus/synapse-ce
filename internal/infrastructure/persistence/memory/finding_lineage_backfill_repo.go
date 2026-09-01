package memory

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type FindingLineageBackfillRepository struct {
	mu      sync.Mutex
	runs    map[shared.ID]map[shared.ID]ports.FindingLineageBackfillRun
	items   map[shared.ID]map[shared.ID]map[shared.ID]ports.FindingLineageBackfillItem
	sources map[shared.ID][]ports.FindingLineageBackfillSourceRow
}

func NewFindingLineageBackfillRepository() *FindingLineageBackfillRepository {
	return &FindingLineageBackfillRepository{
		runs:    map[shared.ID]map[shared.ID]ports.FindingLineageBackfillRun{},
		items:   map[shared.ID]map[shared.ID]map[shared.ID]ports.FindingLineageBackfillItem{},
		sources: map[shared.ID][]ports.FindingLineageBackfillSourceRow{},
	}
}

var _ ports.FindingLineageBackfillSource = (*FindingLineageBackfillRepository)(nil)
var _ ports.FindingLineageBackfillStore = (*FindingLineageBackfillRepository)(nil)

func (repository *FindingLineageBackfillRepository) SetSources(tenantID shared.ID, sources []ports.FindingLineageBackfillSourceRow) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	tenantID = shared.TenantOrDefault(tenantID)
	repository.sources[tenantID] = append([]ports.FindingLineageBackfillSourceRow(nil), sources...)
	sort.Slice(repository.sources[tenantID], func(left, right int) bool {
		return repository.sources[tenantID][left].FindingID < repository.sources[tenantID][right].FindingID
	})
}

func (repository *FindingLineageBackfillRepository) ListFindingLineageBackfillSources(ctx context.Context, tenantID, after shared.ID, snapshotAt time.Time, producerFilters []string, limit int) ([]ports.FindingLineageBackfillSourceRow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 2000 || snapshotAt.IsZero() {
		return nil, fmt.Errorf("%w: finding lineage backfill source query is invalid", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	allowed := map[string]struct{}{}
	for _, producer := range producerFilters {
		allowed[producer] = struct{}{}
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	out := make([]ports.FindingLineageBackfillSourceRow, 0, limit)
	for _, source := range repository.sources[tenantID] {
		if source.FindingID <= after || source.ObservedAt.After(snapshotAt) {
			continue
		}
		if len(allowed) > 0 {
			kind := string(source.Kind)
			if kind == "" {
				kind = "sca"
			}
			if _, ok := allowed[kind]; !ok {
				continue
			}
		}
		out = append(out, source)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (repository *FindingLineageBackfillRepository) AcquireFindingLineageBackfillRun(_ context.Context, request ports.FindingLineageBackfillAcquireRequest) (ports.FindingLineageBackfillRun, bool, error) {
	if err := validateFindingLineageBackfillAcquire(request); err != nil {
		return ports.FindingLineageBackfillRun{}, false, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	tenantRuns := repository.runs[request.Run.TenantID]
	if tenantRuns == nil {
		tenantRuns = map[shared.ID]ports.FindingLineageBackfillRun{}
		repository.runs[request.Run.TenantID] = tenantRuns
	}
	for id, run := range tenantRuns {
		if run.State != ports.FindingLineageBackfillRunning {
			continue
		}
		if run.LeaseOwner != request.Run.LeaseOwner && run.LeaseExpiresAt.After(request.Run.CreatedAt) {
			return ports.FindingLineageBackfillRun{}, false, fmt.Errorf("%w: finding lineage backfill already running for tenant", shared.ErrConflict)
		}
		if run.DryRun != request.Run.DryRun || run.BatchSize != request.Run.BatchSize || strings.Join(run.ProducerFilters, "\x00") != strings.Join(request.Run.ProducerFilters, "\x00") {
			return ports.FindingLineageBackfillRun{}, false, fmt.Errorf("%w: resumed finding lineage backfill options changed", shared.ErrConflict)
		}
		run.LeaseOwner, run.LeaseExpiresAt, run.UpdatedAt = request.Run.LeaseOwner, request.Run.CreatedAt.Add(request.LeaseDuration), request.Run.CreatedAt
		tenantRuns[id] = run
		return cloneFindingLineageBackfillRun(run), true, nil
	}
	run := request.Run
	run.CheckpointFinding = request.InitialCheckpoint
	run.LeaseExpiresAt = run.CreatedAt.Add(request.LeaseDuration)
	tenantRuns[run.ID] = run
	return cloneFindingLineageBackfillRun(run), false, nil
}

func (repository *FindingLineageBackfillRepository) GetFindingLineageBackfillRun(_ context.Context, tenantID, runID shared.ID) (ports.FindingLineageBackfillRun, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	run, ok := repository.runs[shared.TenantOrDefault(tenantID)][runID]
	if !ok {
		return ports.FindingLineageBackfillRun{}, shared.ErrNotFound
	}
	return cloneFindingLineageBackfillRun(run), nil
}

func (repository *FindingLineageBackfillRepository) GetFindingLineageBackfillItem(_ context.Context, tenantID, runID, sourceFindingID shared.ID) (ports.FindingLineageBackfillItem, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	item, ok := repository.items[shared.TenantOrDefault(tenantID)][runID][sourceFindingID]
	if !ok {
		return ports.FindingLineageBackfillItem{}, shared.ErrNotFound
	}
	return item, nil
}

func (repository *FindingLineageBackfillRepository) SaveFindingLineageBackfillItem(_ context.Context, item ports.FindingLineageBackfillItem) (bool, error) {
	if err := validateFindingLineageBackfillItem(item); err != nil {
		return false, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	run, ok := repository.runs[item.TenantID][item.RunID]
	if !ok {
		return false, shared.ErrNotFound
	}
	if run.State != ports.FindingLineageBackfillRunning {
		return false, fmt.Errorf("%w: finding lineage backfill run is not active", shared.ErrConflict)
	}
	tenantItems := repository.items[item.TenantID]
	if tenantItems == nil {
		tenantItems = map[shared.ID]map[shared.ID]ports.FindingLineageBackfillItem{}
		repository.items[item.TenantID] = tenantItems
	}
	runItems := tenantItems[item.RunID]
	if runItems == nil {
		runItems = map[shared.ID]ports.FindingLineageBackfillItem{}
		tenantItems[item.RunID] = runItems
	}
	if _, exists := runItems[item.SourceFindingID]; exists {
		return false, nil
	}
	runItems[item.SourceFindingID] = item
	return true, nil
}

func (repository *FindingLineageBackfillRepository) AdvanceFindingLineageBackfillRun(_ context.Context, tenantID, runID shared.ID, leaseOwner string, checkpoint shared.ID, now time.Time, leaseDuration time.Duration) (ports.FindingLineageBackfillRun, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	tenantID = shared.TenantOrDefault(tenantID)
	run, ok := repository.runs[tenantID][runID]
	if !ok {
		return ports.FindingLineageBackfillRun{}, shared.ErrNotFound
	}
	if run.State != ports.FindingLineageBackfillRunning || run.LeaseOwner != strings.TrimSpace(leaseOwner) || checkpoint < run.CheckpointFinding || leaseDuration <= 0 {
		return ports.FindingLineageBackfillRun{}, fmt.Errorf("%w: finding lineage backfill checkpoint rejected", shared.ErrConflict)
	}
	run.CheckpointFinding, run.UpdatedAt, run.LeaseExpiresAt = checkpoint, now.UTC(), now.UTC().Add(leaseDuration)
	recomputeFindingLineageBackfillCounts(&run, repository.items[tenantID][runID])
	repository.runs[tenantID][runID] = run
	return cloneFindingLineageBackfillRun(run), nil
}

func (repository *FindingLineageBackfillRepository) FinishFindingLineageBackfillRun(_ context.Context, tenantID, runID shared.ID, leaseOwner string, state ports.FindingLineageBackfillState, now time.Time) (ports.FindingLineageBackfillRun, error) {
	if state != ports.FindingLineageBackfillCompleted && state != ports.FindingLineageBackfillCancelled && state != ports.FindingLineageBackfillFailed {
		return ports.FindingLineageBackfillRun{}, fmt.Errorf("%w: invalid finding lineage backfill terminal state", shared.ErrValidation)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	tenantID = shared.TenantOrDefault(tenantID)
	run, ok := repository.runs[tenantID][runID]
	if !ok {
		return ports.FindingLineageBackfillRun{}, shared.ErrNotFound
	}
	if run.State != ports.FindingLineageBackfillRunning || run.LeaseOwner != strings.TrimSpace(leaseOwner) {
		return ports.FindingLineageBackfillRun{}, fmt.Errorf("%w: finding lineage backfill completion rejected", shared.ErrConflict)
	}
	completedAt := now.UTC()
	run.State, run.UpdatedAt, run.CompletedAt = state, completedAt, &completedAt
	run.LeaseOwner, run.LeaseExpiresAt = "", time.Time{}
	recomputeFindingLineageBackfillCounts(&run, repository.items[tenantID][runID])
	repository.runs[tenantID][runID] = run
	return cloneFindingLineageBackfillRun(run), nil
}

func validateFindingLineageBackfillAcquire(request ports.FindingLineageBackfillAcquireRequest) error {
	run := request.Run
	if run.TenantID.IsZero() || run.ID.IsZero() || run.SchemaVersion <= 0 || run.BatchSize < 1 || run.BatchSize > 2000 || run.SnapshotAt.IsZero() || run.State != ports.FindingLineageBackfillRunning || strings.TrimSpace(run.LeaseOwner) == "" || len(run.LeaseOwner) > 256 || run.LeaseExpiresAt.IsZero() || strings.TrimSpace(run.CreatedBy) == "" || len(run.CreatedBy) > 256 || run.CreatedAt.IsZero() || request.LeaseDuration <= 0 {
		return fmt.Errorf("%w: finding lineage backfill run is invalid", shared.ErrValidation)
	}
	return nil
}

func validateFindingLineageBackfillItem(item ports.FindingLineageBackfillItem) error {
	validOutcome := item.Outcome == "observation_created" || item.Outcome == "provisional_candidate_created" || item.Outcome == "skipped"
	_, hashErr := hex.DecodeString(item.SourceHash)
	if item.TenantID.IsZero() || item.RunID.IsZero() || item.AssessmentID.IsZero() || item.SourceFindingID.IsZero() || item.SchemaVersion <= 0 || item.MatcherVersion <= 0 || strings.TrimSpace(item.IdempotencyKey) == "" || len(item.IdempotencyKey) > 128 || len(item.SourceHash) != 64 || strings.ToLower(item.SourceHash) != item.SourceHash || hashErr != nil || !validOutcome || !validBackfillReasonCode(item.ReasonCode) || item.ProcessedAt.IsZero() {
		return fmt.Errorf("%w: finding lineage backfill item is invalid", shared.ErrValidation)
	}
	if item.Outcome != "skipped" && (item.CycleID.IsZero() || item.SnapshotID.IsZero()) {
		return fmt.Errorf("%w: created lineage backfill outcome requires Cycle and Snapshot", shared.ErrValidation)
	}
	return nil
}

func validBackfillReasonCode(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if char != '_' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func recomputeFindingLineageBackfillCounts(run *ports.FindingLineageBackfillRun, items map[shared.ID]ports.FindingLineageBackfillItem) {
	run.ProcessedCount, run.ObservationCreatedCount, run.ProvisionalCandidateCount, run.SkippedCount = 0, 0, 0, 0
	for _, item := range items {
		run.ProcessedCount++
		switch item.Outcome {
		case "observation_created":
			run.ObservationCreatedCount++
		case "provisional_candidate_created":
			run.ProvisionalCandidateCount++
		case "skipped":
			run.SkippedCount++
		}
	}
}

func cloneFindingLineageBackfillRun(run ports.FindingLineageBackfillRun) ports.FindingLineageBackfillRun {
	run.ProducerFilters = append([]string(nil), run.ProducerFilters...)
	if run.CompletedAt != nil {
		completedAt := *run.CompletedAt
		run.CompletedAt = &completedAt
	}
	return run
}
