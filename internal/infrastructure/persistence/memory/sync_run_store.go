package memory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityintel"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilitysync"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type SyncRunStore struct {
	mu     sync.Mutex
	start  sync.Mutex
	ids    ports.IDGenerator
	now    func() time.Time
	queue  ports.JobQueue
	runs   map[shared.ID]vulnerabilitysync.Run
	tenant map[shared.ID]shared.ID
}

func NewSyncRunStore(ids ports.IDGenerator, now func() time.Time, queue ports.JobQueue) *SyncRunStore {
	if now == nil {
		now = time.Now
	}
	return &SyncRunStore{ids: ids, now: now, queue: queue, runs: map[shared.ID]vulnerabilitysync.Run{}, tenant: map[shared.ID]shared.ID{}}
}

var _ ports.SyncRunStore = (*SyncRunStore)(nil)
var _ ports.VulnerabilitySyncRunReadStore = (*SyncRunStore)(nil)

func (s *SyncRunStore) Start(ctx context.Context, request ports.SyncRunStart) (vulnerabilitysync.Run, bool, error) {
	s.start.Lock()
	defer s.start.Unlock()
	if err := validateStart(request); err != nil {
		return vulnerabilitysync.Run{}, false, err
	}
	if _, ok := shared.TenantFrom(ctx); !ok {
		return vulnerabilitysync.Run{}, false, fmt.Errorf("%w: tenant context is required for sync job", shared.ErrValidation)
	}
	s.mu.Lock()
	for _, current := range s.runs {
		if current.SourceID != request.SourceID {
			continue
		}
		if request.ClientIdempotencyKey != "" && current.ClientIdempotencyKey == request.ClientIdempotencyKey {
			s.mu.Unlock()
			return current.Clone(), false, nil
		}
		if current.Mode == request.Mode && !current.State.Terminal() {
			s.mu.Unlock()
			return current.Clone(), false, nil
		}
	}
	if s.ids == nil {
		s.mu.Unlock()
		return vulnerabilitysync.Run{}, false, fmt.Errorf("%w: sync run id generator is nil", shared.ErrValidation)
	}
	now := s.now().UTC()
	checkpoint, _ := vulnerabilitysync.NormalizeCheckpoint(request.Checkpoint)
	snapshot, _ := vulnerabilitysync.NormalizeSourceSnapshot(request.SourceSnapshot)
	tenantID := shared.TenantOrDefault(mustTenant(ctx))
	run := vulnerabilitysync.Run{ID: s.ids.NewID(), SourceID: request.SourceID, AdapterType: request.AdapterType, Mode: request.Mode, Trigger: request.Trigger, Actor: strings.TrimSpace(request.Actor), ClientIdempotencyKey: request.ClientIdempotencyKey, SourceSnapshot: snapshot, Checkpoint: checkpoint, State: vulnerabilitysync.StateQueued, CreatedAt: now, UpdatedAt: now}
	if err := run.Validate(); err != nil {
		s.mu.Unlock()
		return vulnerabilitysync.Run{}, false, err
	}
	if s.queue == nil {
		s.mu.Unlock()
		return vulnerabilitysync.Run{}, false, fmt.Errorf("%w: sync job queue is nil", shared.ErrValidation)
	}
	s.mu.Unlock()
	jobID, err := s.queue.Enqueue(ctx, request.JobKind, request.JobPayload)
	if err != nil {
		return vulnerabilitysync.Run{}, false, fmt.Errorf("enqueue sync job: %w", err)
	}
	run.DurableJobID = jobID
	run.UpdatedAt = s.now().UTC()
	s.mu.Lock()
	s.runs[run.ID] = run
	s.tenant[run.ID] = tenantID
	s.mu.Unlock()
	return run.Clone(), true, nil
}

func (s *SyncRunStore) RecoverStale(ctx context.Context, staleRunID shared.ID, staleBefore time.Time, request ports.SyncRunStart) (vulnerabilitysync.Run, bool, error) {
	s.start.Lock()
	defer s.start.Unlock()
	if staleRunID.IsZero() || staleBefore.IsZero() {
		return vulnerabilitysync.Run{}, false, fmt.Errorf("%w: stale recovery identity is required", shared.ErrValidation)
	}
	if err := validateStart(request); err != nil {
		return vulnerabilitysync.Run{}, false, err
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return vulnerabilitysync.Run{}, false, fmt.Errorf("%w: tenant context is required for sync job", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	s.mu.Lock()
	for _, current := range s.runs {
		if current.SourceID == request.SourceID && request.ClientIdempotencyKey != "" && current.ClientIdempotencyKey == request.ClientIdempotencyKey {
			s.mu.Unlock()
			return current.Clone(), false, nil
		}
	}
	stale, exists := s.runs[staleRunID]
	if !exists || s.tenant[staleRunID] != tenantID {
		s.mu.Unlock()
		return vulnerabilitysync.Run{}, false, shared.ErrNotFound
	}
	if stale.State.Terminal() || !stale.UpdatedAt.Before(staleBefore) {
		s.mu.Unlock()
		return vulnerabilitysync.Run{}, false, shared.ErrConflict
	}
	if request.SourceID != stale.SourceID || request.Mode != stale.Mode {
		s.mu.Unlock()
		return vulnerabilitysync.Run{}, false, fmt.Errorf("%w: stale recovery source or mode mismatch", shared.ErrValidation)
	}
	if s.ids == nil || s.queue == nil {
		s.mu.Unlock()
		return vulnerabilitysync.Run{}, false, fmt.Errorf("%w: sync recovery dependencies are nil", shared.ErrValidation)
	}
	now := s.now().UTC()
	checkpoint, _ := vulnerabilitysync.NormalizeCheckpoint(request.Checkpoint)
	snapshot, _ := vulnerabilitysync.NormalizeSourceSnapshot(request.SourceSnapshot)
	replacement := vulnerabilitysync.Run{
		ID: s.ids.NewID(), SourceID: request.SourceID, AdapterType: request.AdapterType, Mode: request.Mode,
		Trigger: request.Trigger, Actor: strings.TrimSpace(request.Actor), ClientIdempotencyKey: request.ClientIdempotencyKey,
		SourceSnapshot: snapshot, Checkpoint: checkpoint, State: vulnerabilitysync.StateQueued,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := replacement.Validate(); err != nil {
		s.mu.Unlock()
		return vulnerabilitysync.Run{}, false, err
	}
	previous := stale.Clone()
	stale.State, stale.FinishedAt, stale.UpdatedAt = vulnerabilitysync.StateSuperseded, &now, now
	s.runs[staleRunID] = stale
	s.mu.Unlock()
	jobID, err := s.queue.Enqueue(ctx, request.JobKind, request.JobPayload)
	if err != nil {
		s.mu.Lock()
		s.runs[staleRunID] = previous
		s.mu.Unlock()
		return vulnerabilitysync.Run{}, false, fmt.Errorf("enqueue recovered sync job: %w", err)
	}
	replacement.DurableJobID = jobID
	s.mu.Lock()
	s.runs[replacement.ID] = replacement
	s.tenant[replacement.ID] = tenantID
	s.mu.Unlock()
	return replacement.Clone(), true, nil
}

func (s *SyncRunStore) Get(ctx context.Context, id shared.ID) (vulnerabilitysync.Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok || !s.visible(ctx, id) {
		return vulnerabilitysync.Run{}, fmt.Errorf("sync run %s: %w", id, shared.ErrNotFound)
	}
	return run.Clone(), nil
}

func (s *SyncRunStore) GetByDurableJobID(ctx context.Context, jobID string) (vulnerabilitysync.Run, error) {
	// Start holds this lock while enqueueing and publishing the run. The in-memory
	// worker can claim the job immediately, so lookup must not observe the gap
	// between those two operations.
	s.start.Lock()
	defer s.start.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, run := range s.runs {
		if run.DurableJobID == jobID && s.visible(ctx, id) {
			return run.Clone(), nil
		}
	}
	return vulnerabilitysync.Run{}, fmt.Errorf("sync job %s: %w", jobID, shared.ErrNotFound)
}

func (s *SyncRunStore) LatestForSource(ctx context.Context, sourceID shared.ID, states []vulnerabilitysync.State) (vulnerabilitysync.Run, error) {
	if sourceID.IsZero() {
		return vulnerabilitysync.Run{}, fmt.Errorf("%w: source id is required", shared.ErrValidation)
	}
	wanted := make(map[vulnerabilitysync.State]struct{}, len(states))
	for _, state := range states {
		if !state.Valid() {
			return vulnerabilitysync.Run{}, fmt.Errorf("%w: invalid sync run state", shared.ErrValidation)
		}
		wanted[state] = struct{}{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var latest vulnerabilitysync.Run
	found := false
	for id, run := range s.runs {
		if run.SourceID != sourceID || !s.visible(ctx, id) {
			continue
		}
		if len(wanted) > 0 {
			if _, ok := wanted[run.State]; !ok {
				continue
			}
		}
		if !found || run.CreatedAt.After(latest.CreatedAt) || run.CreatedAt.Equal(latest.CreatedAt) && run.ID > latest.ID {
			latest, found = run, true
		}
	}
	if !found {
		return vulnerabilitysync.Run{}, shared.ErrNotFound
	}
	return latest.Clone(), nil
}

func (s *SyncRunStore) visible(ctx context.Context, id shared.ID) bool {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return true
	}
	return shared.TenantOrDefault(tenantID) == s.tenant[id]
}

func mustTenant(ctx context.Context) shared.ID {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() {
		return shared.DefaultTenant
	}
	return tenantID
}

func (s *SyncRunStore) MarkRunning(_ context.Context, id shared.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return fmt.Errorf("sync run %s: %w", id, shared.ErrNotFound)
	}
	if run.State == vulnerabilitysync.StateRunning {
		return nil
	}
	if run.State != vulnerabilitysync.StateQueued {
		return shared.ErrConflict
	}
	now := s.now().UTC()
	run.State, run.StartedAt, run.UpdatedAt = vulnerabilitysync.StateRunning, &now, now
	s.runs[id] = run
	return nil
}

func (s *SyncRunStore) Advance(_ context.Context, id shared.ID, expectedCheckpoint, nextCheckpoint []byte, counts vulnerabilitysync.Counts, errors []string) (vulnerabilitysync.Run, error) {
	if err := counts.Validate(); err != nil {
		return vulnerabilitysync.Run{}, err
	}
	checkpoint, err := vulnerabilitysync.NormalizeCheckpoint(nextCheckpoint)
	if err != nil {
		return vulnerabilitysync.Run{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return vulnerabilitysync.Run{}, shared.ErrNotFound
	}
	if run.State != vulnerabilitysync.StateRunning {
		return vulnerabilitysync.Run{}, shared.ErrConflict
	}
	current, _ := vulnerabilitysync.NormalizeCheckpoint(expectedCheckpoint)
	if string(run.Checkpoint) != string(current) {
		return run.Clone(), shared.ErrConflict
	}
	run.Checkpoint, run.Counts, run.ErrorSamples, run.UpdatedAt = checkpoint, counts, append([]string(nil), errors...), s.now().UTC()
	run.ErrorSamples = trimErrors(run.ErrorSamples)
	s.runs[id] = run
	return run.Clone(), nil
}

func (s *SyncRunStore) Finish(_ context.Context, id shared.ID, state vulnerabilitysync.State, counts vulnerabilitysync.Counts, errors []string) (vulnerabilitysync.Run, error) {
	if !state.Terminal() || state == vulnerabilitysync.StateSuperseded {
		return vulnerabilitysync.Run{}, fmt.Errorf("%w: invalid terminal sync state", shared.ErrValidation)
	}
	if err := counts.Validate(); err != nil {
		return vulnerabilitysync.Run{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return vulnerabilitysync.Run{}, shared.ErrNotFound
	}
	if run.State.Terminal() {
		return run.Clone(), nil
	}
	now := s.now().UTC()
	run.State, run.Counts, run.ErrorSamples, run.FinishedAt, run.UpdatedAt = state, counts, trimErrors(errors), &now, now
	s.runs[id] = run
	return run.Clone(), nil
}

func (s *SyncRunStore) Supersede(_ context.Context, id shared.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return shared.ErrNotFound
	}
	if run.State.Terminal() {
		return nil
	}
	now := s.now().UTC()
	run.State, run.FinishedAt, run.UpdatedAt = vulnerabilitysync.StateSuperseded, &now, now
	s.runs[id] = run
	return nil
}

func (s *SyncRunStore) ListStale(ctx context.Context, olderThan time.Time, limit int) ([]vulnerabilitysync.Run, error) {
	if limit <= 0 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]vulnerabilitysync.Run, 0)
	for id, run := range s.runs {
		if s.visible(ctx, id) && (run.State == vulnerabilitysync.StateQueued || run.State == vulnerabilitysync.StateRunning) && run.UpdatedAt.Before(olderThan) {
			out = append(out, run.Clone())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.Before(out[j].UpdatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *SyncRunStore) ListVulnerabilitySyncRuns(ctx context.Context, query vulnerabilityintel.SyncRunQuery) (vulnerabilityintel.SyncRunPage, error) {
	contextTenant, ok := shared.TenantFrom(ctx)
	query.TenantID = shared.TenantOrDefault(query.TenantID)
	if !ok || shared.TenantOrDefault(contextTenant) != query.TenantID {
		return vulnerabilityintel.SyncRunPage{}, fmt.Errorf("%w: sync run query tenant does not match context", shared.ErrValidation)
	}
	query.Limit = vulnerabilityintel.NormalizeLimit(query.Limit)
	query.Trigger = strings.TrimSpace(query.Trigger)
	if !query.CreatedAtFrom.IsZero() && !query.CreatedAtBefore.IsZero() && !query.CreatedAtFrom.Before(query.CreatedAtBefore) {
		return vulnerabilityintel.SyncRunPage{}, fmt.Errorf("%w: sync run date range is invalid", shared.ErrValidation)
	}
	states := make(map[vulnerabilitysync.State]struct{}, len(query.States))
	for _, state := range query.States {
		if !state.Valid() {
			return vulnerabilityintel.SyncRunPage{}, fmt.Errorf("%w: invalid sync run state", shared.ErrValidation)
		}
		states[state] = struct{}{}
	}
	modes := make(map[vulnerabilitysync.Mode]struct{}, len(query.Modes))
	for _, mode := range query.Modes {
		if !mode.Valid() {
			return vulnerabilityintel.SyncRunPage{}, fmt.Errorf("%w: invalid sync run mode", shared.ErrValidation)
		}
		modes[mode] = struct{}{}
	}
	s.mu.Lock()
	runs := make([]vulnerabilitysync.Run, 0)
	for id, item := range s.runs {
		if s.tenant[id] != query.TenantID || !query.SourceID.IsZero() && item.SourceID != query.SourceID || query.Trigger != "" && item.Trigger != query.Trigger {
			continue
		}
		if !query.CreatedAtFrom.IsZero() && item.CreatedAt.Before(query.CreatedAtFrom) || !query.CreatedAtBefore.IsZero() && !item.CreatedAt.Before(query.CreatedAtBefore) {
			continue
		}
		if len(states) > 0 {
			if _, ok := states[item.State]; !ok {
				continue
			}
		}
		if len(modes) > 0 {
			if _, ok := modes[item.Mode]; !ok {
				continue
			}
		}
		if !query.Cursor.BeforeTime.IsZero() && (item.CreatedAt.After(query.Cursor.BeforeTime) || item.CreatedAt.Equal(query.Cursor.BeforeTime) && item.ID.String() >= query.Cursor.BeforeID) {
			continue
		}
		runs = append(runs, item.Clone())
	}
	s.mu.Unlock()
	sort.Slice(runs, func(i, j int) bool {
		if runs[i].CreatedAt.Equal(runs[j].CreatedAt) {
			return runs[i].ID > runs[j].ID
		}
		return runs[i].CreatedAt.After(runs[j].CreatedAt)
	})
	page := vulnerabilityintel.SyncRunPage{}
	if len(runs) > query.Limit {
		last := runs[query.Limit-1]
		page.Next = &vulnerabilityintel.Cursor{BeforeTime: last.CreatedAt, BeforeID: last.ID.String()}
		runs = runs[:query.Limit]
	}
	page.Items = make([]vulnerabilityintel.SyncRunItem, 0, len(runs))
	for _, run := range runs {
		item, err := s.syncRunItem(ctx, run)
		if err != nil {
			return vulnerabilityintel.SyncRunPage{}, err
		}
		page.Items = append(page.Items, item)
	}
	return page, nil
}

func (s *SyncRunStore) GetVulnerabilitySyncRun(ctx context.Context, tenantID, id shared.ID) (vulnerabilityintel.SyncRunItem, error) {
	tenantID = shared.TenantOrDefault(tenantID)
	contextTenant, ok := shared.TenantFrom(ctx)
	if !ok || shared.TenantOrDefault(contextTenant) != tenantID {
		return vulnerabilityintel.SyncRunItem{}, fmt.Errorf("%w: sync run tenant does not match context", shared.ErrValidation)
	}
	run, err := s.Get(ctx, id)
	if err != nil {
		return vulnerabilityintel.SyncRunItem{}, err
	}
	return s.syncRunItem(ctx, run)
}

func (s *SyncRunStore) syncRunItem(ctx context.Context, run vulnerabilitysync.Run) (vulnerabilityintel.SyncRunItem, error) {
	reader, ok := s.queue.(ports.JobStatusReader)
	if !ok {
		return vulnerabilityintel.SyncRunItem{}, fmt.Errorf("%w: sync job status reader is unavailable", shared.ErrValidation)
	}
	status, err := reader.JobStatus(ctx, run.DurableJobID)
	if err != nil {
		return vulnerabilityintel.SyncRunItem{}, err
	}
	return vulnerabilityintel.SyncRunItem{Run: run.Clone(), Attempts: status.Attempts, DeadLettered: status.DeadLettered}, nil
}

func (s *SyncRunStore) LatestSuccessfulVulnerabilitySync(ctx context.Context, tenantID shared.ID) (*time.Time, error) {
	contextTenant, ok := shared.TenantFrom(ctx)
	tenantID = shared.TenantOrDefault(tenantID)
	if !ok || shared.TenantOrDefault(contextTenant) != tenantID {
		return nil, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var latest *time.Time
	for id, run := range s.runs {
		if s.tenant[id] != tenantID || run.State != vulnerabilitysync.StateSucceeded || run.FinishedAt == nil {
			continue
		}
		if latest == nil || run.FinishedAt.After(*latest) {
			value := *run.FinishedAt
			latest = &value
		}
	}
	return latest, nil
}

func validateStart(request ports.SyncRunStart) error {
	if request.SourceID.IsZero() || request.AdapterType == "" || !request.Mode.Valid() || request.Trigger == "" || strings.TrimSpace(request.Actor) == "" || len(request.Actor) > vulnerabilitysync.MaxActorBytes || request.JobKind == "" {
		return fmt.Errorf("%w: invalid sync start request", shared.ErrValidation)
	}
	if len(request.JobPayload) > 1<<20 {
		return fmt.Errorf("%w: sync job payload is too large", shared.ErrValidation)
	}
	if _, err := vulnerabilitysync.NormalizeCheckpoint(request.Checkpoint); err != nil {
		return err
	}
	_, err := vulnerabilitysync.NormalizeSourceSnapshot(request.SourceSnapshot)
	return err
}

func trimErrors(samples []string) []string {
	out := make([]string, 0, len(samples))
	for _, sample := range samples {
		out = vulnerabilitysync.AddErrorSample(out, sample)
	}
	return out
}
