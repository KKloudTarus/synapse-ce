package memory

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
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
	if err := q.Complete(ctx, id); err != nil {
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
}

func TestJobQueueFailBacksOff(t *testing.T) {
	clk := &movableClock{t: time.Unix(1000, 0).UTC()}
	q := NewJobQueue(&seqIDs{}, clk.now)
	ctx := shared.WithTenant(context.Background(), "tenant-test")
	id, _ := q.Enqueue(ctx, "recon", nil)
	_, _ = q.Claim(ctx, 30*time.Second)
	// Fail with a 60s backoff: not claimable until the backoff elapses.
	if err := q.Fail(ctx, id, 60*time.Second); err != nil {
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
	if err := q.Complete(ctx, "nope"); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("complete missing → ErrNotFound, got %v", err)
	}
	if err := q.Heartbeat(ctx, "nope", time.Second); !errors.Is(err, shared.ErrNotFound) {
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
	_, _ = q.Claim(ctx, time.Minute, "agent")
	if d, _ := q.Depth(ctx, "agent"); d != 2 {
		t.Fatalf("a claimed job must still count, agent depth = %d, want 2", d)
	}
	// Terminal jobs drop out: complete one agent job, dead-letter the recon job.
	_ = q.Complete(ctx, a)
	_ = q.Deadletter(ctx, b)
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
