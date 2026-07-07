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

// TestWorkerRecoversFromHandlerPanic proves a panicking handler (e.g. a crafted image that panics a stdlib
// parser in the SCA handler) is converted to a job failure and does NOT crash the shared worker. If the panic
// were not recovered it would unwind out of the Run goroutine and crash this test process.
func TestWorkerRecoversFromHandlerPanic(t *testing.T) {
	q := memory.NewJobQueue(&seqIDs{}, nil)
	if _, err := q.Enqueue(context.Background(), "boom", []byte("x")); err != nil {
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
	ctx := context.Background()
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

func TestWorkerRetriesThenGivesUp(t *testing.T) {
	q := memory.NewJobQueue(&seqIDs{}, nil)
	_, _ = q.Enqueue(context.Background(), "flaky", nil)

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
	if j, _ := q.Claim(context.Background(), time.Second); j != nil {
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
	_, _ = q.Enqueue(context.Background(), "agent", []byte("sess-payload"))

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
	if j, _ := q.Claim(context.Background(), time.Second); j != nil {
		t.Errorf("job must be dead-lettered after give-up, got %+v", j)
	}
}

func TestWorkerParksUnknownKind(t *testing.T) {
	q := memory.NewJobQueue(&seqIDs{}, nil)
	_, _ = q.Enqueue(context.Background(), "mystery", nil)
	w := New(q, map[string]Handler{}, cfg(), nil) // no handlers

	runFor(t, w, func(cancel context.CancelFunc) {
		time.Sleep(100 * time.Millisecond)
		cancel()
	})
	// An unknown kind is parked (Completed) so it doesn't spin forever.
	if j, _ := q.Claim(context.Background(), time.Second); j != nil {
		t.Errorf("an unknown-kind job must be parked, got %+v", j)
	}
}
