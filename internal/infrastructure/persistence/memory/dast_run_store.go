package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// DASTRunStore is the in-memory DAST run lifecycle store used in local development and tests.
type DASTRunStore struct {
	mu    sync.RWMutex
	runs  map[string]dastrun.Run
	queue ports.JobQueue
}

var _ ports.DASTRunStore = (*DASTRunStore)(nil)
var _ ports.DASTRunEnqueuer = (*DASTRunStore)(nil)

func NewDASTRunStore() *DASTRunStore { return &DASTRunStore{runs: map[string]dastrun.Run{}} }

// runKey mirrors the Postgres primary key (tenant_id, id): a run id is only unique within its tenant, so
// keying by id alone would let one tenant's run overwrite another's. Keeping the composite key here keeps
// the memory store's tenant isolation at parity with the RLS-backed Postgres store.
func runKey(tenantID, id shared.ID) string { return tenantID.String() + "\x00" + id.String() }

// SaveDASTRun upserts the run but never moves a terminal row backward, matching the Postgres store: once a
// run is 'succeeded' or 'failed' its record is frozen, so a stale write cannot un-terminalize it.
func (s *DASTRunStore) SaveDASTRun(_ context.Context, run dastrun.Run) error {
	if err := run.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := runKey(run.TenantID, run.ID)
	if cur, ok := s.runs[k]; ok && cur.Status.Terminal() {
		return nil // terminal runs are immutable
	}
	s.runs[k] = run
	return nil
}

func (s *DASTRunStore) GetDASTRun(_ context.Context, tenantID, id shared.ID) (dastrun.Run, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	run, ok := s.runs[runKey(tenantID, id)]
	if !ok {
		return dastrun.Run{}, fmt.Errorf("%w: DAST run", shared.ErrNotFound)
	}
	return run, nil
}

// StartRun moves a run queued -> running only if the stored run is still queued (compare-and-set),
// reporting whether it won. A worker that finds the run already running or terminal loses and must not probe.
func (s *DASTRunStore) StartRun(_ context.Context, tenantID shared.ID, run dastrun.Run) (bool, error) {
	if run.Status != dastrun.RunRunning {
		return false, fmt.Errorf("%w: StartRun needs a running run, got %s", shared.ErrValidation, run.Status)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := runKey(tenantID, run.ID)
	cur, ok := s.runs[k]
	if !ok {
		return false, fmt.Errorf("%w: DAST run", shared.ErrNotFound)
	}
	if cur.Status != dastrun.RunQueued {
		return false, nil // lost the start race: another delivery already started or finished it
	}
	s.runs[k] = run
	return true, nil
}

// FinishRun writes the terminal run only if the stored run is still running (compare-and-set).
func (s *DASTRunStore) FinishRun(_ context.Context, tenantID shared.ID, run dastrun.Run) (bool, error) {
	if err := run.Validate(); err != nil {
		return false, err
	}
	if !run.Status.Terminal() {
		return false, fmt.Errorf("%w: FinishRun needs a terminal run, got %s", shared.ErrValidation, run.Status)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := runKey(tenantID, run.ID)
	cur, ok := s.runs[k]
	if !ok {
		return false, fmt.Errorf("%w: DAST run", shared.ErrNotFound)
	}
	if cur.Status != dastrun.RunRunning {
		return false, nil // another delivery already terminalized it
	}
	s.runs[k] = run
	return true, nil
}

// SetQueue binds the in-memory queue so EnqueueDASTRun can persist the run and enqueue its job together.
func (s *DASTRunStore) SetQueue(queue ports.JobQueue) { s.queue = queue }

func (s *DASTRunStore) EnqueueDASTRun(ctx context.Context, run dastrun.Run, kind string, payload []byte) error {
	if s.queue == nil {
		return fmt.Errorf("%w: in-memory DAST queue is not bound", shared.ErrValidation)
	}
	if err := s.SaveDASTRun(ctx, run); err != nil {
		return err
	}
	if _, err := s.queue.Enqueue(ctx, kind, payload); err != nil {
		s.mu.Lock()
		delete(s.runs, runKey(run.TenantID, run.ID))
		s.mu.Unlock()
		return err
	}
	return nil
}
