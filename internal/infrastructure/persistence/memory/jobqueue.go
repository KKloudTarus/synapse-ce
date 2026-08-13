package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// JobQueue is an in-memory ports.JobQueue for dev/single-process + tests, with the same
// visibility-lease + reclaim semantics as the Postgres adapter (not durable across
// restarts). Time is injected so tests can exercise lease expiry deterministically.
type JobQueue struct {
	ids   ports.IDGenerator
	now   func() time.Time
	mu    sync.Mutex
	jobs  map[string]*memJob
	order []string // insertion order, for stable FIFO-ish claiming by available_at
}

type memJob struct {
	id           string
	tenantID     shared.ID
	kind         string
	payload      []byte
	status       string // queued | claimed | done
	attempts     int
	availableAt  time.Time
	claimedUntil time.Time
}

// NewJobQueue returns an in-memory job queue. now may be nil (uses time.Now).
func NewJobQueue(ids ports.IDGenerator, now func() time.Time) *JobQueue {
	if now == nil {
		now = time.Now
	}
	return &JobQueue{ids: ids, now: now, jobs: map[string]*memJob{}}
}

var _ ports.JobQueue = (*JobQueue)(nil)
var _ ports.JobStatusReader = (*JobQueue)(nil)

func (q *JobQueue) Enqueue(ctx context.Context, kind string, payload []byte) (string, error) {
	if kind == "" {
		return "", fmt.Errorf("%w: job kind is required", shared.ErrValidation)
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return "", fmt.Errorf("%w: tenant context is required for durable job", shared.ErrValidation)
	}
	id := q.ids.NewID().String()
	q.mu.Lock()
	defer q.mu.Unlock()
	q.jobs[id] = &memJob{id: id, tenantID: tenantID, kind: kind, payload: payload, status: "queued", availableAt: q.now()}
	q.order = append(q.order, id)
	return id, nil
}

// kindWanted reports whether kind is in the filter (empty filter = any kind).
func kindWanted(kind string, kinds []string) bool {
	if len(kinds) == 0 {
		return true
	}
	for _, k := range kinds {
		if k == kind {
			return true
		}
	}
	return false
}

func (q *JobQueue) Claim(_ context.Context, visibility time.Duration, kinds ...string) (*ports.QueuedJob, error) {
	now := q.now()
	q.mu.Lock()
	defer q.mu.Unlock()
	// Candidates: not done, available, of a wanted kind, and either queued or lease-expired.
	var ready []*memJob
	for _, id := range q.order {
		j := q.jobs[id]
		if j == nil || j.status == "done" || j.availableAt.After(now) || !kindWanted(j.kind, kinds) {
			continue
		}
		if j.status == "queued" || (j.status == "claimed" && j.claimedUntil.Before(now)) {
			ready = append(ready, j)
		}
	}
	if len(ready) == 0 {
		return nil, nil
	}
	sort.SliceStable(ready, func(i, k int) bool { return ready[i].availableAt.Before(ready[k].availableAt) })
	j := ready[0]
	j.status = "claimed"
	j.attempts++
	j.claimedUntil = now.Add(visibility)
	return &ports.QueuedJob{ID: j.id, TenantID: j.tenantID, Kind: j.kind, Payload: j.payload, Attempts: j.attempts}, nil
}

func (q *JobQueue) Heartbeat(_ context.Context, id string, extend time.Duration) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	j := q.jobs[id]
	if j == nil || j.status != "claimed" {
		return fmt.Errorf("job %s: %w", id, shared.ErrNotFound)
	}
	j.claimedUntil = q.now().Add(extend)
	return nil
}

func (q *JobQueue) Complete(_ context.Context, id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	j := q.jobs[id]
	if j == nil {
		return fmt.Errorf("job %s: %w", id, shared.ErrNotFound)
	}
	j.status = "done"
	return nil
}

func (q *JobQueue) Deadletter(_ context.Context, id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	j := q.jobs[id]
	if j == nil {
		return fmt.Errorf("job %s: %w", id, shared.ErrNotFound)
	}
	j.status = "failed" // terminal, distinct from done (gave up after MaxAttempts)
	return nil
}

// Depth counts not-yet-terminal jobs (queued or claimed); 'done'/'failed' are excluded.
// Optional kind filter (empty = any). Mirrors the Postgres adapter.
func (q *JobQueue) Depth(_ context.Context, kinds ...string) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := 0
	for _, j := range q.jobs {
		if j == nil || !kindWanted(j.kind, kinds) {
			continue
		}
		if j.status == "queued" || j.status == "claimed" {
			n++
		}
	}
	return n, nil
}

func (q *JobQueue) Stats(_ context.Context, kinds ...string) (ports.JobStats, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	var stats ports.JobStats
	for _, job := range q.jobs {
		if job == nil || !kindWanted(job.kind, kinds) {
			continue
		}
		switch job.status {
		case "queued":
			stats.Queued++
		case "claimed":
			stats.Claimed++
		case "failed":
			stats.Failed++
		case "done":
			stats.Done++
		}
		if job.status == "queued" || job.status == "claimed" {
			at := job.availableAt.UTC()
			if stats.OldestActiveAt == nil || at.Before(*stats.OldestActiveAt) {
				stats.OldestActiveAt = &at
			}
		}
	}
	return stats, nil
}

func (q *JobQueue) JobStatus(ctx context.Context, id string) (ports.JobStatus, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return ports.JobStatus{}, fmt.Errorf("%w: tenant context is required for job status", shared.ErrValidation)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	job := q.jobs[id]
	if job == nil || job.tenantID != shared.TenantOrDefault(tenantID) {
		return ports.JobStatus{}, fmt.Errorf("job %s: %w", id, shared.ErrNotFound)
	}
	return ports.JobStatus{Attempts: job.attempts, DeadLettered: job.status == "failed"}, nil
}

func (q *JobQueue) Fail(_ context.Context, id string, retryIn time.Duration) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	j := q.jobs[id]
	if j == nil {
		return fmt.Errorf("job %s: %w", id, shared.ErrNotFound)
	}
	j.status = "queued"
	j.claimedUntil = time.Time{}
	j.availableAt = q.now().Add(retryIn)
	return nil
}
