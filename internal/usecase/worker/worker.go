// Package worker is the durable-queue claim-loop: it pulls jobs from a
// ports.JobQueue, dispatches each to a Handler registered by Kind, heartbeats long runs
// so their lease does not expire mid-flight, and Completes or Fails (with backoff) the
// job. It is the process body of synapse-worker, and reusable in-process. It owns no
// business logic – the handlers (recon/SCA) carry the same gate/audit/
// evidence invariants as the synchronous path.
package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
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

// DeadLetterer is an optional capability a Handler may implement after the fenced queue
// transition has successfully dead-lettered a terminally failed job. Running it after the
// fence check prevents a stale worker from finalizing entity state owned by a newer claim.
// Best-effort: an OnDeadLetter error is logged after the authoritative queue transition.
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
	if job.TenantID.IsZero() {
		// Defensive guard: durable Enqueue requires a tenant and the tenant-scoped claim never
		// returns a tenant-less row, so this is unreachable in practice. If it ever fired we could
		// not park the job either — every queue mutation is tenant-scoped (RLS) and there is no
		// tenant to scope one with – so skip it and log loudly rather than claim a terminal
		// transition we cannot make.
		w.log.Error("job has no tenant – skipping (cannot tenant-scope a terminal transition)", "kind", job.Kind, "job", job.ID)
		return
	}
	jobCtx := shared.WithTenant(ctx, job.TenantID)
	h, ok := w.handlers[job.Kind]
	if !ok {
		// Unknown kind: there is no handler in this build. Park it (Complete) so it does
		// not spin forever, and log loudly – a silent drop would hide a misconfiguration.
		w.log.Error("no handler for job kind – parking job", "kind", job.Kind, "job", job.ID)
		w.complete(jobCtx, job.ID, job.Fence)
		return
	}

	// The handler runs under a claim-scoped context the heartbeat cancels the moment the lease
	// is lost. Without this a reclaimed job's handler keeps executing – hitting real hosts and
	// publishing domain state or evidence – while another worker owns the job at a newer fence.
	claimCtx, abandonClaim := context.WithCancel(jobCtx)
	defer abandonClaim()
	// Lease loss is recorded explicitly: the claim context is also cancelled on the normal path
	// (handler returned, shutdown), so its error cannot distinguish the two.
	var leaseLost atomic.Bool
	hbDone := make(chan struct{})
	go func() {
		defer close(hbDone)
		w.heartbeat(claimCtx, job.ID, job.Fence, func() {
			leaseLost.Store(true)
			abandonClaim()
		})
	}()

	err := w.safeHandle(claimCtx, h, job)
	// Stop heartbeating and join the goroutine before acting on the result, so the lease-loss
	// signal cannot land after we have decided the job's terminal state.
	abandonClaim()
	<-hbDone

	// The lease was lost mid-flight: another worker owns this job at a newer fence. Abandon it
	// silently without publishing terminal state or evidence.
	if leaseLost.Load() {
		w.log.Warn("job claim was lost during execution – abandoning", "kind", job.Kind, "job", job.ID)
		return
	}
	if errors.Is(err, ports.ErrRetryable) {
		if rerr := w.queue.Retry(context.WithoutCancel(jobCtx), job.ID, job.Fence, w.cfg.Backoff); rerr != nil {
			if errors.Is(rerr, ports.ErrStaleLease) {
				w.log.Warn("job was reclaimed by another worker – abandoning", "job", job.ID, "err", rerr)
			} else {
				w.log.Error("retryable job release failed", "job", job.ID, "err", rerr)
			}
		}
		return
	}
	if err == nil {
		w.complete(jobCtx, job.ID, job.Fence)
		return
	}
	if job.Attempts >= w.cfg.MaxAttempts {
		w.log.Error("job failed permanently – dead-lettering", "kind", job.Kind, "job", job.ID, "attempts", job.Attempts, "err", err)
		// Claim the terminal transition through the fence FIRST. A worker whose lease expired
		// must never drive the backing entity terminal: another worker may already own this job
		// at a newer fence, and the domain repositories are unconditional upserts that would
		// clobber its live run. ErrStaleLease here means we lost the job – abandon silently.
		if derr := w.queue.Deadletter(context.WithoutCancel(jobCtx), job.ID, job.Fence); derr != nil {
			if errors.Is(derr, ports.ErrStaleLease) {
				w.log.Warn("job was reclaimed by another worker – abandoning", "job", job.ID, "err", derr)
			} else {
				w.log.Error("dead-letter failed", "job", job.ID, "err", derr)
			}
			return
		}
		// Terminal FAILED state (not done) is now recorded, so an abandoned authorized scan stays
		// operator-visible + queryable. Drive the backing domain entity terminal too, so a
		// reconciler keyed on the entity's status stops re-enqueuing it – closing the
		// dead-letter → re-drive livelock. Best-effort + logged; a crash between the two leaves
		// the entity to the existing stranded-job reconciler.
		if dl, ok := h.(DeadLetterer); ok {
			if derr := dl.OnDeadLetter(context.WithoutCancel(jobCtx), job, err); derr != nil {
				w.log.Error("dead-letter entity finalize failed", "kind", job.Kind, "job", job.ID, "err", derr)
			}
		}
		return
	}
	w.log.Warn("job failed – requeueing with backoff", "kind", job.Kind, "job", job.ID, "attempt", job.Attempts, "err", err)
	if ferr := w.queue.Fail(jobCtx, job.ID, job.Fence, w.cfg.Backoff); ferr != nil {
		if errors.Is(ferr, ports.ErrStaleLease) {
			w.log.Warn("job was reclaimed by another worker – abandoning", "job", job.ID, "err", ferr)
			return
		}
		w.log.Error("requeue failed", "job", job.ID, "err", ferr)
	}
}

// heartbeat extends the job's lease on an interval until its context is cancelled (the
// handler returned). Each extension runs under a bounded timeout derived from the visibility
// lease so a stalled queue call cannot leak this goroutine or delay lease-loss detection.
// Losing the lease calls abandon, cancelling the handler: another worker owns the job now, and
// continued execution would hit real hosts and publish state behind that worker's back.
func (w *Worker) heartbeat(ctx context.Context, id string, fence int64, abandon context.CancelFunc) {
	t := time.NewTicker(w.cfg.Heartbeat)
	defer t.Stop()
	leaseDeadline := time.Now().Add(w.cfg.Visibility)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			remaining := time.Until(leaseDeadline)
			if remaining <= 0 {
				w.log.Warn("job lease expired after heartbeat failure – abandoning", "job", id)
				abandon()
				return
			}
			// A heartbeat cannot wait beyond the last lease known to be authoritative. If the
			// queue is unavailable through that deadline, another worker may reclaim this job.
			hbCtx, cancel := context.WithTimeout(ctx, remaining)
			err := w.queue.Heartbeat(hbCtx, id, fence, w.cfg.Visibility)
			cancel()
			if err == nil {
				leaseDeadline = time.Now().Add(w.cfg.Visibility)
				continue
			}
			if errors.Is(err, ports.ErrStaleLease) {
				w.log.Warn("job was reclaimed by another worker – abandoning", "job", id, "err", err)
				abandon()
				return
			}
			w.log.Warn("heartbeat failed", "job", id, "err", err)
			if time.Now().After(leaseDeadline) {
				w.log.Warn("job lease expired after heartbeat failure – abandoning", "job", id)
				abandon()
				return
			}
		}
	}
}

func (w *Worker) complete(ctx context.Context, id string, fence int64) {
	if err := w.queue.Complete(context.WithoutCancel(ctx), id, fence); err != nil {
		if errors.Is(err, ports.ErrStaleLease) {
			w.log.Warn("job was reclaimed by another worker – abandoning", "job", id, "err", err)
			return
		}
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
