package memory

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// CloudRunStore is the in-memory CSPM lifecycle store used in local development and tests.
type CloudRunStore struct {
	mu    sync.RWMutex
	runs  map[shared.ID]cloudposture.Run
	jobs  map[shared.ID]cloudRunJobRecord
	queue ports.JobQueue
}

type cloudRunJobRecord struct {
	kind    string
	payload []byte
	ready   bool
}

var _ ports.CloudRunStore = (*CloudRunStore)(nil)
var _ ports.CloudRunEnqueuer = (*CloudRunStore)(nil)
var _ ports.CloudRunJobReader = (*CloudRunStore)(nil)
var _ ports.CloudRunAuthorizationReader = (*CloudRunStore)(nil)

func NewCloudRunStore() *CloudRunStore {
	return &CloudRunStore{runs: map[shared.ID]cloudposture.Run{}, jobs: map[shared.ID]cloudRunJobRecord{}}
}

func (s *CloudRunStore) SaveCloudRun(_ context.Context, run cloudposture.Run) error {
	if err := run.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if prior, ok := s.runs[run.ID]; ok {
		if prior.TenantID != run.TenantID || prior.EngagementID != run.EngagementID || prior.Actor != run.Actor || !prior.StartedAt.Truncate(time.Microsecond).Equal(run.StartedAt.Truncate(time.Microsecond)) {
			return fmt.Errorf("%w: CSPM run identity mismatch", shared.ErrValidation)
		}
		if prior.Status == cloudposture.RunCancelled && sameCloudRun(prior, run) {
			return nil
		}
		if prior.Status.Terminal() && (!run.Status.Terminal() || prior.Status == cloudposture.RunCancelled || run.Status == cloudposture.RunCancelled) {
			return fmt.Errorf("%w: CSPM run is terminal", shared.ErrForbidden)
		}
	}
	s.runs[run.ID] = cloneCloudRun(run)
	return nil
}

func sameCloudRun(a, b cloudposture.Run) bool {
	if a.ID != b.ID || a.TenantID != b.TenantID || a.EngagementID != b.EngagementID || a.Actor != b.Actor || a.Status != b.Status || a.Complete != b.Complete || a.Assets != b.Assets || a.Findings != b.Findings || a.ErrorCode != b.ErrorCode || !slices.Equal(a.CoverageIssues, b.CoverageIssues) || !slices.Equal(a.EvidenceRefs, b.EvidenceRefs) || !a.StartedAt.Truncate(time.Microsecond).Equal(b.StartedAt.Truncate(time.Microsecond)) {
		return false
	}
	if a.FinishedAt == nil || b.FinishedAt == nil {
		return a.FinishedAt == nil && b.FinishedAt == nil
	}
	return a.FinishedAt.Truncate(time.Microsecond).Equal(b.FinishedAt.Truncate(time.Microsecond))
}

func (s *CloudRunStore) GetCloudRun(_ context.Context, tenantID, id shared.ID) (cloudposture.Run, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	run, ok := s.runs[id]
	if !ok || run.TenantID != tenantID {
		return cloudposture.Run{}, fmt.Errorf("%w: CSPM run", shared.ErrNotFound)
	}
	return cloneCloudRun(run), nil
}

func (s *CloudRunStore) SetQueue(queue ports.JobQueue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue = queue
}

func (s *CloudRunStore) EnqueueCloudRun(ctx context.Context, run cloudposture.Run, kind string, payload []byte) error {
	if err := run.Validate(); err != nil {
		return err
	}
	if tenant, ok := shared.TenantFrom(ctx); !ok || tenant != run.TenantID {
		return fmt.Errorf("%w: CSPM queue tenant mismatch", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.queue == nil {
		return fmt.Errorf("%w: in-memory CSPM queue is not bound", shared.ErrValidation)
	}
	if _, exists := s.runs[run.ID]; exists {
		return fmt.Errorf("%w: CSPM run already exists", shared.ErrValidation)
	}
	record := cloudRunJobRecord{kind: kind, payload: append([]byte(nil), payload...)}
	queued := false
	deferred := registerTenantCommit(ctx, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !queued {
			return
		}
		if committed, ok := s.jobs[run.ID]; ok {
			committed.ready = true
			s.jobs[run.ID] = committed
		}
	})
	if _, err := s.queue.Enqueue(ctx, kind, payload); err != nil {
		return err
	}
	s.runs[run.ID] = cloneCloudRun(run)
	record.ready = !deferred
	s.jobs[run.ID] = record
	queued = true
	registerTenantRollback(ctx, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.runs, run.ID)
		delete(s.jobs, run.ID)
	})
	return nil
}

func (s *CloudRunStore) cloudRunJob(tenantID, id shared.ID) (cloudposture.Run, ports.CloudRunJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	run, ok := s.runs[id]
	if !ok || run.TenantID != tenantID {
		return cloudposture.Run{}, ports.CloudRunJob{}, fmt.Errorf("%w: CSPM run", shared.ErrNotFound)
	}
	record, ok := s.jobs[id]
	if !ok || !record.ready {
		return cloudposture.Run{}, ports.CloudRunJob{}, fmt.Errorf("%w: CSPM job missing", shared.ErrForbidden)
	}
	job, err := ports.DecodeCloudRunJob(run, record.kind, record.payload)
	if err != nil {
		return cloudposture.Run{}, ports.CloudRunJob{}, err
	}
	return cloneCloudRun(run), job, nil
}

func (s *CloudRunStore) GetCloudRunJob(_ context.Context, tenantID, id shared.ID) (ports.CloudRunJob, error) {
	_, job, err := s.cloudRunJob(tenantID, id)
	return job, err
}

func (s *CloudRunStore) GetCloudRunAuthorization(_ context.Context, tenantID, id shared.ID) (ports.CloudRunAuthorization, error) {
	run, job, err := s.cloudRunJob(tenantID, id)
	if err != nil {
		return ports.CloudRunAuthorization{}, err
	}
	return ports.CloudAuthorizationFromJob(run, job), nil
}

func cloneCloudRun(run cloudposture.Run) cloudposture.Run {
	run.CoverageIssues = append([]cloudposture.CoverageIssue(nil), run.CoverageIssues...)
	run.EvidenceRefs = append([]cloudposture.EvidenceReference(nil), run.EvidenceRefs...)
	if run.FinishedAt != nil {
		finished := *run.FinishedAt
		run.FinishedAt = &finished
	}
	return run
}
