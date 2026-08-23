package worker

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
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

// runFor runs the worker until the assertion goroutine cancels (work done) or a timeout.
func runFor(t *testing.T, w *Worker, ready func(cancel context.CancelFunc)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { _ = w.Run(ctx); close(done) }()
	ready(cancel)
	<-done
}

func cfg() Config {
	return Config{Visibility: time.Second, Poll: 5 * time.Millisecond, Heartbeat: 200 * time.Millisecond, Backoff: 10 * time.Millisecond, MaxAttempts: 3}
}

type staleCompleteQueue struct {
	completeCalls   atomic.Int64
	failCalls       atomic.Int64
	deadletterCalls atomic.Int64
}

func (q *staleCompleteQueue) Enqueue(context.Context, string, []byte) (string, error) {
	return "", nil
}
func (q *staleCompleteQueue) Claim(context.Context, time.Duration, ...string) (*ports.QueuedJob, error) {
	return nil, nil
}
func (q *staleCompleteQueue) Heartbeat(context.Context, string, int64, time.Duration) error {
	return nil
}
func (q *staleCompleteQueue) Complete(context.Context, string, int64) error {
	q.completeCalls.Add(1)
	return ports.ErrStaleLease
}
func (q *staleCompleteQueue) Fail(context.Context, string, int64, time.Duration) error {
	q.failCalls.Add(1)
	return nil
}
func (q *staleCompleteQueue) Retry(context.Context, string, int64, time.Duration) error {
	return nil
}
func (q *staleCompleteQueue) Deadletter(context.Context, string, int64) error {
	q.deadletterCalls.Add(1)
	return nil
}
func (q *staleCompleteQueue) Depth(context.Context, ...string) (int, error) { return 0, nil }
func (q *staleCompleteQueue) Stats(context.Context, ...string) (ports.JobStats, error) {
	return ports.JobStats{}, nil
}

func TestWorkerAbandonsStaleCompletion(t *testing.T) {
	q := &staleCompleteQueue{}
	w := New(q, map[string]Handler{
		"recon": HandlerFunc(func(context.Context, ports.QueuedJob) error { return nil }),
	}, cfg(), nil)

	w.process(context.Background(), ports.QueuedJob{
		ID:       "job-1",
		TenantID: "tenant-test",
		Kind:     "recon",
		Fence:    7,
	})

	if q.completeCalls.Load() != 1 {
		t.Fatalf("Complete calls = %d, want 1", q.completeCalls.Load())
	}
	if q.failCalls.Load() != 0 || q.deadletterCalls.Load() != 0 {
		t.Fatalf("stale completion must abandon without Fail or Deadletter: fail=%d deadletter=%d", q.failCalls.Load(), q.deadletterCalls.Load())
	}
}

// TestWorkerRecoversFromHandlerPanic proves a panicking handler (e.g. a crafted image that panics a stdlib
// parser in the SCA handler) is converted to a job failure and does NOT crash the shared worker. If the panic
// were not recovered it would unwind out of the Run goroutine and crash this test process.
func TestWorkerRecoversFromHandlerPanic(t *testing.T) {
	q := memory.NewJobQueue(&seqIDs{}, nil)
	ctx := shared.WithTenant(context.Background(), "tenant-test")
	if _, err := q.Enqueue(ctx, "boom", []byte("x")); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	w := New(q, map[string]Handler{
		"boom": HandlerFunc(func(_ context.Context, _ ports.QueuedJob) error {
			calls.Add(1)
			panic("crafted-binary parser exploded")
		}),
	}, cfg(), nil)

	runFor(t, w, func(cancel context.CancelFunc) {
		for i := 0; i < 200; i++ {
			if calls.Load() >= 1 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	})
	if calls.Load() < 1 {
		t.Fatal("the panicking handler was never invoked")
	}
	// Reaching here (Run returned on cancel) proves the panic did not crash the worker.
}

func TestWorkerProcessesAndCompletes(t *testing.T) {
	q := memory.NewJobQueue(&seqIDs{}, nil)
	ctx := shared.WithTenant(context.Background(), "tenant-test")
	id, _ := q.Enqueue(ctx, "recon", []byte("payload"))

	var handled atomic.Int64
	var gotPayload atomic.Value
	w := New(q, map[string]Handler{
		"recon": HandlerFunc(func(_ context.Context, j ports.QueuedJob) error {
			gotPayload.Store(string(j.Payload))
			handled.Add(1)
			return nil
		}),
	}, cfg(), nil)

	runFor(t, w, func(cancel context.CancelFunc) {
		for i := 0; i < 200; i++ {
			if handled.Load() == 1 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	})

	if handled.Load() != 1 {
		t.Fatalf("expected the job handled once, got %d", handled.Load())
	}
	if gotPayload.Load() != "payload" {
		t.Errorf("handler saw payload %v", gotPayload.Load())
	}
	// Completed → not redelivered.
	if j, _ := q.Claim(ctx, time.Second); j != nil {
		t.Errorf("a completed job must not be claimable, got %+v (id %s)", j, id)
	}
}

func TestWorkerRetryableResultDoesNotBurnAttempt(t *testing.T) {
	q := memory.NewJobQueue(&seqIDs{}, nil)
	ctx := shared.WithTenant(context.Background(), "tenant-test")
	id, err := q.Enqueue(ctx, "contended", nil)
	if err != nil {
		t.Fatal(err)
	}
	job, err := q.Claim(ctx, time.Second)
	if err != nil || job == nil {
		t.Fatalf("claim = %+v, %v", job, err)
	}
	w := New(q, map[string]Handler{
		"contended": HandlerFunc(func(context.Context, ports.QueuedJob) error { return ports.ErrRetryable }),
	}, cfg(), nil)
	w.process(context.Background(), *job)

	status, err := q.JobStatus(ctx, id)
	if err != nil || status.Attempts != 0 || status.DeadLettered {
		t.Fatalf("retryable status = %+v, %v; want zero attempts and a live job", status, err)
	}
	if next, err := q.Claim(ctx, time.Second); err != nil || next != nil {
		t.Fatalf("retryable job ignored backoff: claim=%+v err=%v", next, err)
	}
}

func TestWorkerRetriesThenGivesUp(t *testing.T) {
	q := memory.NewJobQueue(&seqIDs{}, nil)
	ctx := shared.WithTenant(context.Background(), "tenant-test")
	_, _ = q.Enqueue(ctx, "flaky", nil)

	var calls atomic.Int64
	w := New(q, map[string]Handler{
		"flaky": HandlerFunc(func(_ context.Context, _ ports.QueuedJob) error {
			calls.Add(1)
			return errors.New("boom")
		}),
	}, cfg(), nil)

	runFor(t, w, func(cancel context.CancelFunc) {
		// MaxAttempts=3 → handler called at most 3 times, then dead-lettered.
		for i := 0; i < 400; i++ {
			if calls.Load() >= 3 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond) // let it settle (no 4th call)
		cancel()
	})

	if got := calls.Load(); got != 3 {
		t.Fatalf("expected exactly MaxAttempts=3 handler calls, got %d", got)
	}
	if j, _ := q.Claim(ctx, time.Second); j != nil {
		t.Errorf("after giving up, the job must be dead-lettered (not claimable), got %+v", j)
	}
}

// deadLetterHandler always fails and records the OnDeadLetter callback so the test can assert
// the worker drove the entity-finalize hook on give-up.
type deadLetterHandler struct {
	mu        sync.Mutex
	dlCalls   int
	lastCause error
	lastJob   ports.QueuedJob
}

func (h *deadLetterHandler) Handle(_ context.Context, _ ports.QueuedJob) error {
	return errors.New("boom")
}

func (h *deadLetterHandler) OnDeadLetter(_ context.Context, job ports.QueuedJob, cause error) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dlCalls++
	h.lastCause = cause
	h.lastJob = job
	return nil
}

func TestWorkerCallsDeadLettererOnGiveUp(t *testing.T) {
	q := memory.NewJobQueue(&seqIDs{}, nil)
	ctx := shared.WithTenant(context.Background(), "tenant-test")
	_, _ = q.Enqueue(ctx, "agent", []byte("sess-payload"))

	h := &deadLetterHandler{}
	w := New(q, map[string]Handler{"agent": h}, cfg(), nil)

	runFor(t, w, func(cancel context.CancelFunc) {
		for i := 0; i < 400; i++ {
			h.mu.Lock()
			done := h.dlCalls >= 1
			h.mu.Unlock()
			if done {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(30 * time.Millisecond) // let it settle (no second finalize)
		cancel()
	})

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.dlCalls != 1 {
		t.Fatalf("OnDeadLetter must fire exactly once on give-up, got %d", h.dlCalls)
	}
	if h.lastCause == nil || h.lastCause.Error() != "boom" {
		t.Errorf("OnDeadLetter must receive the last handler error, got %v", h.lastCause)
	}
	if string(h.lastJob.Payload) != "sess-payload" {
		t.Errorf("OnDeadLetter must receive the dead-lettered job, got payload %q", h.lastJob.Payload)
	}
	// The job is still dead-lettered (the hook does not block it).
	if j, _ := q.Claim(ctx, time.Second); j != nil {
		t.Errorf("job must be dead-lettered after give-up, got %+v", j)
	}
}

// staleDeadletterQueue reports that the job was reclaimed at a newer fence when the worker
// tries to dead-letter it.
type staleDeadletterQueue struct {
	staleCompleteQueue
}

func (q *staleDeadletterQueue) Complete(context.Context, string, int64) error {
	q.completeCalls.Add(1)
	return nil
}

func (q *staleDeadletterQueue) Deadletter(context.Context, string, int64) error {
	q.deadletterCalls.Add(1)
	return ports.ErrStaleLease
}

// TestWorkerSkipsDeadLettererWhenLeaseIsStale proves the fence check gates the entity finalize.
// The backing domain repositories are unconditional upserts, so a worker whose lease expired must
// not drive the entity terminal: the job already belongs to another worker at a newer fence and
// that worker's live run would be clobbered.
func TestWorkerSkipsDeadLettererWhenLeaseIsStale(t *testing.T) {
	q := &staleDeadletterQueue{}
	h := &deadLetterHandler{}
	w := New(q, map[string]Handler{"agent": h}, cfg(), nil)

	w.process(context.Background(), ports.QueuedJob{
		ID:       "job-1",
		TenantID: "tenant-test",
		Kind:     "agent",
		Fence:    3,
		Attempts: cfg().MaxAttempts,
	})

	if q.deadletterCalls.Load() != 1 {
		t.Fatalf("Deadletter calls = %d, want 1", q.deadletterCalls.Load())
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.dlCalls != 0 {
		t.Fatalf("OnDeadLetter must not fire after a stale lease, got %d calls", h.dlCalls)
	}
}

// staleHeartbeatQueue reports the lease as lost on the first heartbeat, simulating another
// worker reclaiming the job after this worker's visibility lease expired.
type staleHeartbeatQueue struct {
	staleCompleteQueue
	heartbeats atomic.Int64
}

func (q *staleHeartbeatQueue) Heartbeat(context.Context, string, int64, time.Duration) error {
	q.heartbeats.Add(1)
	return ports.ErrStaleLease
}

func (q *staleHeartbeatQueue) Complete(context.Context, string, int64) error {
	q.completeCalls.Add(1)
	return nil
}

// TestWorkerCancelsHandlerWhenLeaseIsLost proves losing the lease mid-flight cancels the
// handler's context and abandons the job. Recon handlers hit real hosts and seal evidence, so a
// handler that keeps running after another worker has reclaimed the job at a newer fence would
// publish state behind that worker's back and could double-complete the work.
func TestWorkerCancelsHandlerWhenLeaseIsLost(t *testing.T) {
	q := &staleHeartbeatQueue{}
	handlerCtxErr := make(chan error, 1)
	w := New(q, map[string]Handler{
		"recon": HandlerFunc(func(ctx context.Context, _ ports.QueuedJob) error {
			// Model a long tool run: block until the lease is lost (ctx cancelled).
			select {
			case <-ctx.Done():
				handlerCtxErr <- ctx.Err()
				return ctx.Err()
			case <-time.After(3 * time.Second):
				handlerCtxErr <- nil
				return nil
			}
		}),
	}, Config{Visibility: time.Second, Poll: 5 * time.Millisecond, Heartbeat: 10 * time.Millisecond, Backoff: 10 * time.Millisecond, MaxAttempts: 3}, nil)

	w.process(context.Background(), ports.QueuedJob{
		ID:       "job-1",
		TenantID: "tenant-test",
		Kind:     "recon",
		Fence:    5,
	})

	select {
	case err := <-handlerCtxErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("handler context error = %v, want context.Canceled", err)
		}
	default:
		t.Fatal("handler did not observe cancellation")
	}
	if q.heartbeats.Load() == 0 {
		t.Fatal("heartbeat must run so lease loss is detected")
	}
	// A reclaimed job must not have its terminal state published by this worker.
	if q.completeCalls.Load() != 0 || q.failCalls.Load() != 0 || q.deadletterCalls.Load() != 0 {
		t.Fatalf("lost claim must publish no terminal state: complete=%d fail=%d deadletter=%d",
			q.completeCalls.Load(), q.failCalls.Load(), q.deadletterCalls.Load())
	}
}

type failingHeartbeatQueue struct {
	staleCompleteQueue
	heartbeats atomic.Int64
}

func (q *failingHeartbeatQueue) Heartbeat(context.Context, string, int64, time.Duration) error {
	q.heartbeats.Add(1)
	return errors.New("database unavailable")
}

func TestWorkerCancelsHandlerWhenHeartbeatCannotRenewLease(t *testing.T) {
	q := &failingHeartbeatQueue{}
	handlerCtxErr := make(chan error, 1)
	w := New(q, map[string]Handler{
		"recon": HandlerFunc(func(ctx context.Context, _ ports.QueuedJob) error {
			<-ctx.Done()
			handlerCtxErr <- ctx.Err()
			return ctx.Err()
		}),
	}, Config{Visibility: 40 * time.Millisecond, Poll: 5 * time.Millisecond, Heartbeat: 5 * time.Millisecond, Backoff: 10 * time.Millisecond, MaxAttempts: 3}, nil)

	w.process(context.Background(), ports.QueuedJob{
		ID:       "job-1",
		TenantID: "tenant-test",
		Kind:     "recon",
		Fence:    5,
	})

	select {
	case err := <-handlerCtxErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("handler context error = %v, want context.Canceled", err)
		}
	default:
		t.Fatal("handler did not observe cancellation after lease renewal failed")
	}
	if q.heartbeats.Load() == 0 {
		t.Fatal("heartbeat must run before the known lease expires")
	}
	if q.completeCalls.Load() != 0 || q.failCalls.Load() != 0 || q.deadletterCalls.Load() != 0 {
		t.Fatalf("expired claim must publish no terminal state: complete=%d fail=%d deadletter=%d",
			q.completeCalls.Load(), q.failCalls.Load(), q.deadletterCalls.Load())
	}
}

type blockingHeartbeatQueue struct {
	staleCompleteQueue
	started chan struct{}
}

func (q *blockingHeartbeatQueue) Heartbeat(ctx context.Context, _ string, _ int64, _ time.Duration) error {
	select {
	case <-q.started:
	default:
		close(q.started)
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestWorkerHeartbeatHonorsParentCancellation(t *testing.T) {
	q := &blockingHeartbeatQueue{started: make(chan struct{})}
	w := New(q, nil, Config{Visibility: time.Second, Heartbeat: time.Millisecond}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.heartbeat(ctx, "job-1", 1, func() {})
		close(done)
	}()

	select {
	case <-q.started:
	case <-time.After(time.Second):
		t.Fatal("heartbeat did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("heartbeat did not stop after parent cancellation")
	}
}

func TestWorkerParksUnknownKind(t *testing.T) {
	q := memory.NewJobQueue(&seqIDs{}, nil)
	ctx := shared.WithTenant(context.Background(), "tenant-test")
	_, _ = q.Enqueue(ctx, "mystery", nil)
	w := New(q, map[string]Handler{}, cfg(), nil) // no handlers

	runFor(t, w, func(cancel context.CancelFunc) {
		time.Sleep(100 * time.Millisecond)
		cancel()
	})
	// An unknown kind is parked (Completed) so it doesn't spin forever.
	if j, _ := q.Claim(ctx, time.Second); j != nil {
		t.Errorf("an unknown-kind job must be parked, got %+v", j)
	}
}
