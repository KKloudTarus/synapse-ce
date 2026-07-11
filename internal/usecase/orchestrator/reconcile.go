package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// resumableLister + enqueuer are the narrow slices the reconciler needs. enqueuer is defined
// here (not imported from usecase/worker) so the orchestrator stays off the worker package –
// the concrete ports.JobQueue satisfies it.
type resumableLister interface {
	ListResumable(ctx context.Context, staleFor time.Duration, now time.Time, limit int) ([]agent.Session, error)
}
type enqueuer interface {
	Enqueue(ctx context.Context, kind string, payload []byte) (string, error)
}

// Reconciler re-drives agent sessions that a crash stranded. On startup (and periodically) it
// finds non-terminal sessions not touched for staleFor and re-enqueues a Drive job for the
// RUNNING ones. An awaiting_approval session is NEVER auto-driven (a human must decide first);
// it is only logged. This is the durability backstop: without it, a session in `running` whose
// worker died is unrecoverable (Drive is never called on it again).
type Reconciler struct {
	sessions resumableLister
	enqueue  enqueuer
	clock    ports.Clock
	staleFor time.Duration
	limit    int
	log      *slog.Logger
}

// NewReconciler validates deps. staleFor should exceed a healthy run's heartbeat window (e.g.
// AgentMaxDuration + a margin) so a still-live run is not re-enqueued under it.
func NewReconciler(sessions resumableLister, enqueue enqueuer, clock ports.Clock, staleFor time.Duration, log *slog.Logger) (*Reconciler, error) {
	if sessions == nil || enqueue == nil || clock == nil {
		return nil, fmt.Errorf("%w: reconciler is missing a dependency", shared.ErrValidation)
	}
	if staleFor <= 0 {
		staleFor = 15 * time.Minute
	}
	if log == nil {
		log = slog.Default()
	}
	return &Reconciler{sessions: sessions, enqueue: enqueue, clock: clock, staleFor: staleFor, limit: 100, log: log}, nil
}

// ReconcileOnce re-enqueues a Drive job for each stranded running session. Returns the number
// re-enqueued. Idempotent: re-driving is safe (Drive no-ops a terminal session, the run lock
// serializes, and fail-closed per-action idempotency prevents a double-run).
func (r *Reconciler) ReconcileOnce(ctx context.Context) (int, error) {
	sessions, err := r.sessions.ListResumable(ctx, r.staleFor, r.clock.Now(), r.limit)
	if err != nil {
		return 0, fmt.Errorf("list resumable sessions: %w", err)
	}
	n := 0
	for _, sess := range sessions {
		if sess.Status == agent.StatusAwaitingApproval {
			// A human owes a decision; never auto-drive an action that is awaiting approval.
			r.log.Info("reconcile: session awaiting approval (not auto-driven)", "session", sess.ID.String())
			continue
		}
		payload, err := DriveJob(sess.ID)
		if err != nil {
			r.log.Error("reconcile: build drive job", "session", sess.ID.String(), "err", err)
			continue
		}
		if _, err := r.enqueue.Enqueue(ctx, JobKind, payload); err != nil {
			r.log.Error("reconcile: re-enqueue drive job", "session", sess.ID.String(), "err", err)
			continue
		}
		r.log.Info("reconcile: re-enqueued stranded running session", "session", sess.ID.String())
		n++
	}
	return n, nil
}

// Run reconciles once on startup, then on a ticker, until ctx is cancelled.
func (r *Reconciler) Run(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 5 * time.Minute
	}
	if _, err := r.ReconcileOnce(ctx); err != nil && ctx.Err() == nil {
		r.log.Error("reconcile: startup pass failed", "err", err)
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := r.ReconcileOnce(ctx); err != nil && ctx.Err() == nil {
				r.log.Error("reconcile: pass failed", "err", err)
			}
		}
	}
}
