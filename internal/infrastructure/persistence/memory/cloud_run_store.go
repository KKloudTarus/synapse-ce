package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/cloudposture"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// CloudRunStore is the in-memory CSPM lifecycle store used in local development and tests.
type CloudRunStore struct {
	mu    sync.RWMutex
	runs  map[shared.ID]cloudposture.Run
	queue ports.JobQueue
}

var _ ports.CloudRunStore = (*CloudRunStore)(nil)
var _ ports.CloudRunEnqueuer = (*CloudRunStore)(nil)

func NewCloudRunStore() *CloudRunStore { return &CloudRunStore{runs: map[shared.ID]cloudposture.Run{}} }

func (s *CloudRunStore) SaveCloudRun(_ context.Context, run cloudposture.Run) error {
	if err := run.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs[run.ID] = run
	return nil
}

func (s *CloudRunStore) GetCloudRun(_ context.Context, tenantID, id shared.ID) (cloudposture.Run, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	run, ok := s.runs[id]
	if !ok || run.TenantID != tenantID {
		return cloudposture.Run{}, fmt.Errorf("%w: CSPM run", shared.ErrNotFound)
	}
	return run, nil
}

func (s *CloudRunStore) SetQueue(queue ports.JobQueue) { s.queue = queue }

func (s *CloudRunStore) EnqueueCloudRun(ctx context.Context, run cloudposture.Run, kind string, payload []byte) error {
	if s.queue == nil {
		return fmt.Errorf("%w: in-memory CSPM queue is not bound", shared.ErrValidation)
	}
	if err := s.SaveCloudRun(ctx, run); err != nil {
		return err
	}
	if _, err := s.queue.Enqueue(ctx, kind, payload); err != nil {
		s.mu.Lock()
		delete(s.runs, run.ID)
		s.mu.Unlock()
		return err
	}
	return nil
}
