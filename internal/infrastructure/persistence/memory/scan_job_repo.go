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
	if stored, existed := s.byID[j.ID]; !existed {
		s.latest[shared.ID(j.EngagementID)] = j.ID
	} else {
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
	if j.Status == ports.ScanSucceeded && !frozenTerminal {
		j = withMemoryScanBaseline(s.byID, j)
	}
	s.byID[j.ID] = cloneScanJobSource(j)
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
