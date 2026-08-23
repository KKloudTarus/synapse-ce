package memory

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type seqIDs struct {
	mu sync.Mutex
	n  int
}

func (s *seqIDs) NewID() shared.ID {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	return shared.ID("job-" + strconv.Itoa(s.n))
}

type movableClock struct{ t time.Time }

func (c *movableClock) now() time.Time { return c.t }

func TestJobQueueClaimLeaseAndComplete(t *testing.T) {
	clk := &movableClock{t: time.Unix(1000, 0).UTC()}
	q := NewJobQueue(&seqIDs{}, clk.now)
	ctx := shared.WithTenant(context.Background(), "tenant-test")

	id, err := q.Enqueue(ctx, "recon", []byte(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	// First claim hands it out for a 30s lease.
	j, err := q.Claim(ctx, 30*time.Second)
	if err != nil || j == nil || j.ID != id || j.Attempts != 1 {
		t.Fatalf("first claim should return the job (attempt 1): %+v err=%v", j, err)
	}
	// While leased, it is not claimable again.
	if j2, _ := q.Claim(ctx, 30*time.Second); j2 != nil {
		t.Fatalf("a leased job must not be re-claimed, got %+v", j2)
	}
	// Complete → never returned again.
	if err := q.Complete(ctx, id, j.Fence); err != nil {
		t.Fatal(err)
	}
	if j3, _ := q.Claim(ctx, 30*time.Second); j3 != nil {
		t.Fatalf("a completed job must not be claimable, got %+v", j3)
	}
}

func TestJobQueueExpiredLeaseIsReclaimed(t *testing.T) {
	clk := &movableClock{t: time.Unix(1000, 0).UTC()}
	q := NewJobQueue(&seqIDs{}, clk.now)
	ctx := shared.WithTenant(context.Background(), "tenant-test")
	id, _ := q.Enqueue(ctx, "sca", nil)

	first, _ := q.Claim(ctx, 10*time.Second)
	if first == nil {
		t.Fatal("expected first claim")
	}
	// Worker "dies": advance past the lease. The job becomes claimable again.
	clk.t = clk.t.Add(11 * time.Second)
	second, err := q.Claim(ctx, 10*time.Second)
	if err != nil || second == nil || second.ID != id {
		t.Fatalf("an expired lease must be reclaimable: %+v err=%v", second, err)
	}
	if second.Attempts != 2 {
		t.Errorf("reclaim should be attempt 2, got %d", second.Attempts)
	}
	if second.Fence <= first.Fence {
		t.Errorf("reclaim fence = %d, want greater than first fence %d", second.Fence, first.Fence)
	}
}

func TestJobQueueFencesStaleLeaseMutations(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant-test")
	operations := []struct {
		name string
		call func(*JobQueue, string, int64) error
	}{
		{"complete", func(q *JobQueue, id string, fence int64) error { return q.Complete(ctx, id, fence) }},
		{"fail", func(q *JobQueue, id string, fence int64) error { return q.Fail(ctx, id, fence, 0) }},
		{"retry", func(q *JobQueue, id string, fence int64) error { return q.Retry(ctx, id, fence, 0) }},
		{"deadletter", func(q *JobQueue, id string, fence int64) error { return q.Deadletter(ctx, id, fence) }},
		{"heartbeat", func(q *JobQueue, id string, fence int64) error { return q.Heartbeat(ctx, id, fence, time.Minute) }},
	}

	for _, tt := range operations {
		t.Run(tt.name, func(t *testing.T) {
			clk := &movableClock{t: time.Unix(1000, 0).UTC()}
			q := NewJobQueue(&seqIDs{}, clk.now)
			id, err := q.Enqueue(ctx, "recon", nil)
			if err != nil {
				t.Fatal(err)
			}
			first, err := q.Claim(ctx, time.Second)
			if err != nil || first == nil {
				t.Fatalf("first claim = %+v, %v", first, err)
			}
			clk.t = clk.t.Add(2 * time.Second)
			second, err := q.Claim(ctx, time.Minute)
			if err != nil || second == nil || second.Fence <= first.Fence {
				t.Fatalf("reclaim = %+v, %v", second, err)
			}

			if err := tt.call(q, id, first.Fence); !errors.Is(err, ports.ErrStaleLease) {
				t.Fatalf("stale %s error = %v, want ErrStaleLease", tt.name, err)
			}
			j := q.jobs[id]
			if j.status != "claimed" || j.claimFence != second.Fence {
				t.Fatalf("stale %s changed current claim: status=%q fence=%d, want claimed/%d", tt.name, j.status, j.claimFence, second.Fence)
			}
			if got, want := j.claimedUntil, clk.t.Add(time.Minute); !got.Equal(want) {
				t.Fatalf("stale %s changed current lease: got %v, want %v", tt.name, got, want)
			}
		})
	}
}

func TestJobQueueCurrentFenceMutationsSucceed(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "tenant-test")
	operations := []struct {
		name       string
		call       func(*JobQueue, string, int64) error
		wantStatus string
	}{
		{"complete", func(q *JobQueue, id string, fence int64) error { return q.Complete(ctx, id, fence) }, "done"},
		{"fail", func(q *JobQueue, id string, fence int64) error { return q.Fail(ctx, id, fence, 0) }, "queued"},
		{"deadletter", func(q *JobQueue, id string, fence int64) error { return q.Deadletter(ctx, id, fence) }, "failed"},
		{"heartbeat", func(q *JobQueue, id string, fence int64) error { return q.Heartbeat(ctx, id, fence, time.Minute) }, "claimed"},
	}

	for _, tt := range operations {
		t.Run(tt.name, func(t *testing.T) {
			q := NewJobQueue(&seqIDs{}, time.Now)
			id, err := q.Enqueue(ctx, "recon", nil)
			if err != nil {
				t.Fatal(err)
			}
			job, err := q.Claim(ctx, time.Minute)
			if err != nil || job == nil {
				t.Fatalf("claim = %+v, %v", job, err)
			}
			if err := tt.call(q, id, job.Fence); err != nil {
				t.Fatalf("current %s: %v", tt.name, err)
			}
			if got := q.jobs[id].status; got != tt.wantStatus {
				t.Fatalf("status after %s = %q, want %q", tt.name, got, tt.wantStatus)
			}
		})
	}
}

func TestJobQueueFencedMutationsRejectMissingJobs(t *testing.T) {
	q := NewJobQueue(&seqIDs{}, time.Now)
	ctx := shared.WithTenant(context.Background(), "tenant-test")
	operations := []struct {
		name string
		call func() error
	}{
		{"complete", func() error { return q.Complete(ctx, "missing", 1) }},
		{"fail", func() error { return q.Fail(ctx, "missing", 1, 0) }},
		{"deadletter", func() error { return q.Deadletter(ctx, "missing", 1) }},
		{"heartbeat", func() error { return q.Heartbeat(ctx, "missing", 1, time.Minute) }},
	}
	for _, tt := range operations {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); !errors.Is(err, shared.ErrNotFound) || errors.Is(err, ports.ErrStaleLease) {
				t.Fatalf("missing %s error = %v, want ErrNotFound only", tt.name, err)
			}
		})
	}
}

func TestJobQueueReclaimFencesExpiredWorkerCompletion(t *testing.T) {
	clk := &movableClock{t: time.Unix(1000, 0).UTC()}
	q := NewJobQueue(&seqIDs{}, clk.now)
	ctx := shared.WithTenant(context.Background(), "tenant-test")
	id, err := q.Enqueue(ctx, "sca", nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := q.Claim(ctx, time.Second)
	if err != nil || first == nil {
		t.Fatalf("first claim = %+v, %v", first, err)
	}
	clk.t = clk.t.Add(2 * time.Second)
	second, err := q.Claim(ctx, time.Minute)
	if err != nil || second == nil || second.Fence <= first.Fence {
		t.Fatalf("second claim = %+v, %v", second, err)
	}
	if err := q.Complete(ctx, id, first.Fence); !errors.Is(err, ports.ErrStaleLease) {
		t.Fatalf("stale completion = %v, want ErrStaleLease", err)
	}
	if err := q.Complete(ctx, id, second.Fence); err != nil {
		t.Fatalf("current completion: %v", err)
	}
	if j, err := q.Claim(ctx, time.Minute); err != nil || j != nil {
		t.Fatalf("completed exactly once: job=%+v err=%v", j, err)
	}
}

func TestJobQueueRetryBacksOffWithoutBurningAttempt(t *testing.T) {
	clk := &movableClock{t: time.Unix(1000, 0).UTC()}
	q := NewJobQueue(&seqIDs{}, clk.now)
	ctx := shared.WithTenant(context.Background(), "tenant-test")
	id, err := q.Enqueue(ctx, "recon", nil)
	if err != nil {
		t.Fatal(err)
	}
	job, err := q.Claim(ctx, time.Minute)
	if err != nil || job == nil || job.Attempts != 1 {
		t.Fatalf("claim = %+v, %v", job, err)
	}
	if err := q.Retry(ctx, id, job.Fence, time.Minute); err != nil {
		t.Fatal(err)
	}
	status, err := q.JobStatus(ctx, id)
	if err != nil || status.Attempts != 0 {
		t.Fatalf("retry status = %+v, %v; want zero attempts", status, err)
	}
	if next, err := q.Claim(ctx, time.Minute); err != nil || next != nil {
		t.Fatalf("retry ignored backoff: claim=%+v err=%v", next, err)
	}
	clk.t = clk.t.Add(time.Minute)
	next, err := q.Claim(ctx, time.Minute)
	if err != nil || next == nil || next.Attempts != 1 {
		t.Fatalf("reclaimed retry = %+v, %v; want first charged delivery", next, err)
	}
}

func TestJobQueueFailBacksOff(t *testing.T) {
	clk := &movableClock{t: time.Unix(1000, 0).UTC()}
	q := NewJobQueue(&seqIDs{}, clk.now)
	ctx := shared.WithTenant(context.Background(), "tenant-test")
	id, _ := q.Enqueue(ctx, "recon", nil)
	// Fail with a 60s backoff: not claimable until the backoff elapses.
	job, _ := q.Claim(ctx, 30*time.Second)
	if err := q.Fail(ctx, id, job.Fence, 60*time.Second); err != nil {
		t.Fatal(err)
	}
	if j, _ := q.Claim(ctx, 30*time.Second); j != nil {
		t.Fatalf("a failed job must wait out its backoff, got %+v", j)
	}
	clk.t = clk.t.Add(61 * time.Second)
	if j, _ := q.Claim(ctx, 30*time.Second); j == nil {
		t.Fatal("after the backoff, the job should be claimable again")
	}
}

func TestJobQueueErrorsOnMissing(t *testing.T) {
	q := NewJobQueue(&seqIDs{}, (&movableClock{t: time.Unix(1, 0)}).now)
	ctx := shared.WithTenant(context.Background(), "tenant-test")
	if err := q.Complete(ctx, "nope", 1); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("complete missing → ErrNotFound, got %v", err)
	}
	if err := q.Heartbeat(ctx, "nope", 1, time.Second); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("heartbeat missing → ErrNotFound, got %v", err)
	}
}

func TestJobQueueEnqueueRequiresKind(t *testing.T) {
	q := NewJobQueue(&seqIDs{}, nil)
	if _, err := q.Enqueue(context.Background(), "", nil); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty kind → ErrValidation, got %v", err)
	}
}

// TestJobQueueDepth covers durable backpressure: Depth counts not-yet-terminal jobs
// (queued + claimed/in-flight), honors the kind filter, and excludes terminal jobs
// (done + dead-lettered).
func TestJobQueueDepth(t *testing.T) {
	clk := &movableClock{t: time.Unix(1000, 0).UTC()}
	q := NewJobQueue(&seqIDs{}, clk.now)
	ctx := shared.WithTenant(context.Background(), "tenant-test")
	if d, _ := q.Depth(ctx); d != 0 {
		t.Fatalf("empty queue depth = %d, want 0", d)
	}
	a, _ := q.Enqueue(ctx, "agent", nil)
	_, _ = q.Enqueue(ctx, "agent", nil)
	b, _ := q.Enqueue(ctx, "recon", nil)
	if d, _ := q.Depth(ctx); d != 3 {
		t.Fatalf("depth (all kinds) = %d, want 3", d)
	}
	if d, _ := q.Depth(ctx, "agent"); d != 2 {
		t.Fatalf("agent depth = %d, want 2", d)
	}
	// A claimed (in-flight) job still counts toward depth.
	claimedAgent, _ := q.Claim(ctx, time.Minute, "agent")
	if d, _ := q.Depth(ctx, "agent"); d != 2 {
		t.Fatalf("a claimed job must still count, agent depth = %d, want 2", d)
	}
	// Terminal jobs drop out: complete one agent job, dead-letter the recon job.
	_ = q.Complete(ctx, a, claimedAgent.Fence)
	claimedRecon, _ := q.Claim(ctx, time.Minute, "recon")
	_ = q.Deadletter(ctx, b, claimedRecon.Fence)
	if d, _ := q.Depth(ctx, "agent"); d != 1 {
		t.Fatalf("a completed job must drop out, agent depth = %d, want 1", d)
	}
	if d, _ := q.Depth(ctx); d != 1 {
		t.Fatalf("only 1 non-terminal job should remain, got %d", d)
	}
}

// TestJobQueueClaimByKind covers that a worker claims only its kinds, so the recon
// worker and the in-process SCA worker never grab each other's jobs.
func TestJobQueueClaimByKind(t *testing.T) {
	clk := &movableClock{t: time.Unix(1000, 0).UTC()}
	q := NewJobQueue(&seqIDs{}, clk.now)
	ctx := shared.WithTenant(context.Background(), "tenant-test")
	_, _ = q.Enqueue(ctx, "recon", []byte("r"))
	_, _ = q.Enqueue(ctx, "sca", []byte("s"))

	// An SCA worker claims only the sca job, never the recon one.
	j, _ := q.Claim(ctx, time.Minute, "sca")
	if j == nil || j.Kind != "sca" {
		t.Fatalf("an sca worker must claim the sca job, got %+v", j)
	}
	if j2, _ := q.Claim(ctx, time.Minute, "sca"); j2 != nil {
		t.Errorf("an sca worker must NOT claim the recon job, got %+v", j2)
	}
	// A recon worker claims the recon job.
	if j3, _ := q.Claim(ctx, time.Minute, "recon"); j3 == nil || j3.Kind != "recon" {
		t.Fatalf("a recon worker must claim the recon job, got %+v", j3)
	}
}

// TestJobQueueAggregateJobQueueStatsAggregatesAllTenants covers the metrics seam: unlike
// Stats (tenant-scoped by JobStatus's own tenant check), AggregateJobQueueStats must sum
// every job across every tenant, since the in-memory adapter has no per-tenant isolation
// boundary to preserve for a single-process operator collector.
func TestJobQueueAggregateJobQueueStatsAggregatesAllTenants(t *testing.T) {
	clk := &movableClock{t: time.Unix(1000, 0).UTC()}
	q := NewJobQueue(&seqIDs{}, clk.now)
	ctxA := shared.WithTenant(context.Background(), "tenant-a")
	ctxB := shared.WithTenant(context.Background(), "tenant-b")

	_, _ = q.Enqueue(ctxA, "sca", nil)
	_, _ = q.Enqueue(ctxB, "sca", nil)
	_, _ = q.Claim(ctxA, time.Minute, "sca")

	stats, err := q.AggregateJobQueueStats(context.Background(), "sca")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Queued != 1 || stats.Claimed != 1 {
		t.Fatalf("aggregate stats = %+v, want 1 queued + 1 claimed across both tenants", stats)
	}
}
