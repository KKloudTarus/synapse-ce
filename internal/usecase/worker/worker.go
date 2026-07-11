// Package worker is the durable-queue claim-loop: it pulls jobs from a
// ports.JobQueue, dispatches each to a Handler registered by Kind, heartbeats long runs
// so their lease does not expire mid-flight, and Completes or Fails (with backoff) the
// job. It is the process body of synapse-worker, and reusable in-process. It owns no
// business logic – the handlers (recon/SCA) carry the same gate/audit/
// evidence invariants as the synchronous path.
package worker

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Handler processes one claimed job. A nil error means success (the job is Completed);
// any error requeues the job with backoff until MaxAttempts is reached. Handlers must be
// IDEMPOTENT: at-least-once delivery means a job can run more than once (e.g. after a
// crash mid-run), and recon hits real hosts.
type Handler interface {
	Handle(ctx context.Context, job ports.QueuedJob) error
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, job ports.QueuedJob) error

// Handle calls f.
func (f HandlerFunc) Handle(ctx context.Context, job ports.QueuedJob) error { return f(ctx, job) }

// DeadLetterer is an optional capability a Handler may implement. When the worker is about to
// dead-letter a job (terminal failure after MaxAttempts), it calls OnDeadLetter FIRST so the
// handler can drive its backing domain entity (agent session / recon run) to a terminal state.
// Without it, a reconciler that keys on the ENTITY's status – not the job's – re-enqueues the
// stranded entity forever (the dead-letter → re-drive livelock), and the job/entity states
// permanently disagree. Best-effort: an OnDeadLetter error is logged, never blocking the
// dead-letter itself. cause is the last handler error that exhausted the retries.
type DeadLetterer interface {
	OnDeadLetter(ctx context.Context, job ports.QueuedJob, cause error) error
}

// Config tunes the loop; zero values fall back to sane defaults.
type Config struct {
	Visibility  time.Duration // lease per claim
	Poll        time.Duration // idle sleep when the queue is empty
	Heartbeat   time.Duration // lease-extension interval for an in-flight job
	Backoff     time.Duration // base requeue delay on failure
	MaxAttempts int           // give up (dead-letter) after this many deliveries
}

func (c *Config) withDefaults() {
	if c.Visibility <= 0 {
		c.Visibility = 2 * time.Minute
	}
	if c.Poll <= 0 {
		c.Poll = time.Second
	}
	if c.Heartbeat <= 0 {
		c.Heartbeat = c.Visibility / 3
	}
	if c.Backoff <= 0 {
		c.Backoff = 10 * time.Second
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 5
	}
}

// Worker runs the claim/dispatch/complete loop over a JobQueue.
type Worker struct {
	queue    ports.JobQueue
	handlers map[string]Handler
	cfg      Config
	log      *slog.Logger
}

// New builds a worker. handlers maps job Kind → Handler.
func New(queue ports.JobQueue, handlers map[string]Handler, cfg Config, log *slog.Logger) *Worker {
	cfg.withDefaults()
	if log == nil {
		log = slog.Default()
	}
	return &Worker{queue: queue, handlers: handlers, cfg: cfg, log: log}
}

// Run claims and processes jobs until ctx is cancelled (graceful shutdown drains the
// current job, then returns). It never returns on a transient queue error – it logs and
// keeps polling – so a brief DB blip doesn't kill the worker.
func (w *Worker) Run(ctx context.Context) error {
	w.log.Info("worker started", "kinds", w.kinds(), "visibility", w.cfg.Visibility)
	for {
		if ctx.Err() != nil {
			w.log.Info("worker stopped")
			return ctx.Err()
		}
		job, err := w.queue.Claim(ctx, w.cfg.Visibility, w.kinds()...)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			w.log.Error("claim failed", "err", err)
			w.sleep(ctx, w.cfg.Poll)
			continue
		}
		if job == nil {
			w.sleep(ctx, w.cfg.Poll) // queue empty
			continue
		}
		w.process(ctx, *job)
	}
}

// safeHandle runs a job handler, converting a PANIC into an error so one poisoned job – e.g. a crafted
// container image that panics a stdlib binary/archive parser in the SCA handler – fails and retries through
// the normal path instead of unwinding out of the claim loop and crashing the shared worker process.
func (w *Worker) safeHandle(ctx context.Context, h Handler, job ports.QueuedJob) (err error) {
	defer func() {
		if r := recover(); r != nil {
			w.log.Error("job handler panicked – failing job", "kind", job.Kind, "job", job.ID, "panic", r, "stack", string(debug.Stack()))
			err = fmt.Errorf("handler panicked: %v", r)
		}
	}()
	return h.Handle(ctx, job)
}

// process dispatches one job, heartbeating its lease until the handler returns, then
// Completes or Fails it.
func (w *Worker) process(ctx context.Context, job ports.QueuedJob) {
	h, ok := w.handlers[job.Kind]
	if !ok {
		// Unknown kind: there is no handler in this build. Park it (Complete) so it does
		// not spin forever, and log loudly – a silent drop would hide a misconfiguration.
		w.log.Error("no handler for job kind – parking job", "kind", job.Kind, "job", job.ID)
		w.complete(job.ID)
		return
	}

	hbCtx, stopHB := context.WithCancel(ctx)
	go w.heartbeat(hbCtx, job.ID)

	err := w.safeHandle(ctx, h, job)
	stopHB()

	if err == nil {
		w.complete(job.ID)
		return
	}
	if job.Attempts >= w.cfg.MaxAttempts {
		w.log.Error("job failed permanently – dead-lettering", "kind", job.Kind, "job", job.ID, "attempts", job.Attempts, "err", err)
		// Drive the backing domain entity terminal BEFORE flipping the job row, so a reconciler
		// keyed on the entity's status (not the job's) stops re-enqueuing it – closing the
		// dead-letter → re-drive livelock. Best-effort + logged; never blocks the dead-letter.
		if dl, ok := h.(DeadLetterer); ok {
			if derr := dl.OnDeadLetter(context.Background(), job, err); derr != nil {
				w.log.Error("dead-letter entity finalize failed", "kind", job.Kind, "job", job.ID, "err", derr)
			}
		}
		// Terminal FAILED state (not done): an abandoned authorized scan stays operator-
		// visible + queryable, never silently indistinguishable from a success.
		if derr := w.queue.Deadletter(context.Background(), job.ID); derr != nil {
			w.log.Error("dead-letter failed", "job", job.ID, "err", derr)
		}
		return
	}
	w.log.Warn("job failed – requeueing with backoff", "kind", job.Kind, "job", job.ID, "attempt", job.Attempts, "err", err)
	if ferr := w.queue.Fail(ctx, job.ID, w.cfg.Backoff); ferr != nil {
		w.log.Error("requeue failed", "job", job.ID, "err", ferr)
	}
}

// heartbeat extends the job's lease on an interval until its context is cancelled (the
// handler returned). Uses context.Background for the extension call so a cancelled
// parent (shutdown) still lets the in-flight handler finish under a valid lease.
func (w *Worker) heartbeat(ctx context.Context, id string) {
	t := time.NewTicker(w.cfg.Heartbeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := w.queue.Heartbeat(context.Background(), id, w.cfg.Visibility); err != nil {
				w.log.Warn("heartbeat failed", "job", id, "err", err)
			}
		}
	}
}

func (w *Worker) complete(id string) {
	if err := w.queue.Complete(context.Background(), id); err != nil {
		w.log.Error("complete failed", "job", id, "err", err)
	}
}

// sleep waits d, returning early if ctx is cancelled.
func (w *Worker) sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (w *Worker) kinds() []string {
	out := make([]string, 0, len(w.handlers))
	for k := range w.handlers {
		out = append(out, k)
	}
	return out
}

// Enqueuer is the write side a use case uses to defer work to the worker. It is
// the subset of ports.JobQueue producers need.
type Enqueuer interface {
	Enqueue(ctx context.Context, kind string, payload []byte) (string, error)
}

var _ Enqueuer = (ports.JobQueue)(nil)
