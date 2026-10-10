package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ScanJobStore is an in-memory store of asynchronous scan-job status.
type ScanJobStore struct {
	mu     sync.RWMutex
	byID   map[string]ports.ScanJob
	latest map[shared.ID]string // engagement -> latest job id
}

// NewScanJobStore returns an empty in-memory scan-job store.
func NewScanJobStore() *ScanJobStore {
	return &ScanJobStore{byID: map[string]ports.ScanJob{}, latest: map[shared.ID]string{}}
}

var _ ports.ScanJobStore = (*ScanJobStore)(nil)

func (s *ScanJobStore) CreateRunning(_ context.Context, j ports.ScanJob) error {
	if _, err := scanrun.CanonicalEngineOutcomes(j.EngineOutcomes); err != nil {
		return err
	}
	// A notification snapshot is completion evidence. Admission and progress
	// updates must never create one before the first successful terminal save.
	j.NotificationSnapshot = notification.ScanSummary{}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, current := range s.byID {
		// CI imports are already complete in the pipeline. Their short-lived running
		// state must not reserve the engagement's asynchronous scan slot.
		if j.Kind != "ci-import" && current.Kind != "ci-import" && current.EngagementID == j.EngagementID && current.Status == ports.ScanRunning {
			return shared.ErrConflict
		}
	}
	s.byID[j.ID] = cloneScanJobSource(j)
	s.latest[shared.ID(j.EngagementID)] = j.ID
	return nil
}

// Save upserts a job; a newly-seen id becomes the latest for its engagement.
func (s *ScanJobStore) Save(_ context.Context, j ports.ScanJob) error {
	if _, err := scanrun.CanonicalEngineOutcomes(j.EngineOutcomes); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	frozenTerminal := false
	stored, existed := s.byID[j.ID]
	if existed {
		// A first terminal snapshot has to belong to the engagement admitted at
		// CreateRunning. Preserve ordinary status-only corrections, but reject a
		// supplied completion snapshot before normalizing its caller fields.
		if stored.NotificationSnapshot.TargetKey == "" && j.NotificationSnapshot.TargetKey != "" && j.EngagementID != stored.EngagementID {
			return fmt.Errorf("%w: scan notification snapshot does not match admitted engagement", shared.ErrValidation)
		}
		// Match the PostgreSQL status-only upsert: admission identity and source
		// cannot be rewritten by a later progress/status update.
		j.EngagementID, j.Target, j.Kind = stored.EngagementID, stored.Target, stored.Kind
		j.StartedAt = stored.StartedAt
		j.SourcePackage = stored.SourcePackage
		if stored.NotificationSnapshot.TargetKey != "" {
			frozenTerminal = true
			j.FinishedAt = stored.FinishedAt
			j.NotificationSnapshot = stored.NotificationSnapshot.Clone()
		}
	}
	if j.Status != ports.ScanSucceeded && !frozenTerminal {
		// A failed attempt may carry a partial result, but it cannot become
		// notification evidence. A later first success is still allowed to
		// capture its own snapshot.
		j.NotificationSnapshot = notification.ScanSummary{}
	}
	if j.Status == ports.ScanSucceeded && !frozenTerminal {
		if err := validateMemoryScanSnapshotAdmission(j); err != nil {
			return err
		}
		j = withMemoryScanBaseline(s.byID, j)
	}
	if !existed {
		s.latest[shared.ID(j.EngagementID)] = j.ID
	}
	s.byID[j.ID] = cloneScanJobSource(j)
	return nil
}

// validateMemoryScanSnapshotAdmission makes the in-memory adapter enforce the
// same immutable target/kind binding as the PostgreSQL terminal writer. Empty
// snapshots remain supported for legacy jobs, but a supplied snapshot must be
// the one the stored admission can legitimately produce.
func validateMemoryScanSnapshotAdmission(job ports.ScanJob) error {
	if job.NotificationSnapshot.TargetKey == "" {
		return nil
	}
	expected := notification.NewScanSummary(notification.CanonicalScanTarget(job.Target, job.Kind), job.Kind, false, nil)
	if expected.TargetKey == "" || expected.Kind == "" ||
		job.NotificationSnapshot.TargetKey != expected.TargetKey || job.NotificationSnapshot.Kind != expected.Kind {
		return fmt.Errorf("%w: scan notification snapshot does not match admitted target", shared.ErrValidation)
	}
	return nil
}

// withMemoryScanBaseline mirrors the PostgreSQL terminal-save comparison. The
// store lock protects both the predecessor lookup and replacement, so concurrent
// completions for the same target observe a deterministic predecessor.
func withMemoryScanBaseline(jobs map[string]ports.ScanJob, current ports.ScanJob) ports.ScanJob {
	best := ports.ScanJob{}
	for _, candidate := range jobs {
		candidateTargetKey := candidate.NotificationSnapshot.TargetKey
		if candidateTargetKey == "" {
			candidateTargetKey = notification.CanonicalScanTarget(candidate.Target, candidate.Kind)
		}
		if candidate.ID == current.ID || candidate.Status != ports.ScanSucceeded ||
			candidate.EngagementID != current.EngagementID || candidate.Kind != current.Kind ||
			candidateTargetKey != current.NotificationSnapshot.TargetKey ||
			candidate.FinishedAt == nil || current.FinishedAt == nil ||
			candidate.FinishedAt.After(*current.FinishedAt) ||
			(candidate.FinishedAt.Equal(*current.FinishedAt) && candidate.ID >= current.ID) {
			continue
		}
		if best.FinishedAt == nil || candidate.FinishedAt.After(*best.FinishedAt) ||
			(candidate.FinishedAt.Equal(*best.FinishedAt) && candidate.ID > best.ID) {
			best = candidate
		}
	}
	if best.FinishedAt != nil {
		if best.NotificationSnapshot.TargetKey == "" {
			return current
		}
		current.NotificationSnapshot = current.NotificationSnapshot.WithBaselineID(best.NotificationSnapshot, best.ID)
	}
	return current
}

// ListStaleRunning returns jobs still 'running' that started before olderThan (≤ limit),
// oldest first.
func (s *ScanJobStore) ListStaleRunning(_ context.Context, olderThan time.Time, limit int) ([]ports.ScanJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []ports.ScanJob{}
	for _, j := range s.byID {
		if j.Status == ports.ScanRunning && j.StartedAt.Before(olderThan) {
			out = append(out, cloneScanJobSource(j))
		}
	}
	sort.Slice(out, func(i, k int) bool { return out[i].StartedAt.Before(out[k].StartedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// GetJob returns a job by its own id, or ErrNotFound.
func (s *ScanJobStore) GetJob(_ context.Context, id string) (ports.ScanJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.byID[id]
	if !ok {
		return ports.ScanJob{}, fmt.Errorf("scan job %s: %w", id, shared.ErrNotFound)
	}
	return cloneScanJobSource(j), nil
}

// LatestForEngagement returns the engagement's most recent job, or ErrNotFound.
func (s *ScanJobStore) LatestForEngagement(_ context.Context, engagementID shared.ID) (ports.ScanJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.latest[engagementID]
	if !ok {
		return ports.ScanJob{}, fmt.Errorf("scan job for %s: %w", engagementID, shared.ErrNotFound)
	}
	return cloneScanJobSource(s.byID[id]), nil
}

func (s *ScanJobStore) LatestForEngagements(_ context.Context, engagementIDs []shared.ID) (map[shared.ID]ports.ScanJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[shared.ID]ports.ScanJob{}
	for _, engagementID := range engagementIDs {
		if id, ok := s.latest[engagementID]; ok {
			out[engagementID] = cloneScanJobSource(s.byID[id])
		}
	}
	return out, nil
}

func cloneScanJobSource(job ports.ScanJob) ports.ScanJob {
	job.EngineOutcomes = scanrun.CloneEngineOutcomes(job.EngineOutcomes)
	job.EngineCoverage = scanrun.ComputeEngineCoverage(job.EngineOutcomes)
	job.NotificationSnapshot = job.NotificationSnapshot.Clone()
	if job.SourcePackage != nil {
		item := *job.SourcePackage
		item.Locator, item.ObjectKey = "", ""
		job.SourcePackage = &item
	}
	return job
}
