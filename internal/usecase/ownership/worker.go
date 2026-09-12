package ownership

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/ownership"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const RouteJobKind = "ownership.route"

type Worker struct {
	store  ports.OwnershipWorkerStore
	repo   ports.OwnershipRepository
	mode   string
	notify bool
	log    *slog.Logger
}

func NewWorker(store ports.OwnershipWorkerStore, repo ports.OwnershipRepository, mode string, notify bool, log *slog.Logger) (*Worker, error) {
	if store == nil || repo == nil || log == nil || mode != "observe" && mode != "enforce" {
		return nil, shared.ErrValidation
	}
	return &Worker{store: store, repo: repo, mode: mode, notify: notify, log: log}, nil
}

func (w *Worker) StartOwnershipRun(ctx context.Context, req ports.OwnershipRunRequest) (ports.OwnershipRun, error) {
	if req.Mode == "reroute" && w.mode != "enforce" {
		return ports.OwnershipRun{}, ErrWorkerUnavailable
	}
	return w.store.StartOwnershipRun(ctx, req)
}

func (w *Worker) Poll(ctx context.Context) (int, error) {
	return w.store.DispatchOwnership(ctx, w.mode, 100)
}

func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		if n, err := w.Poll(ctx); err != nil && ctx.Err() == nil {
			w.log.Warn("ownership dispatch failed", "err", err)
		} else if n > 0 {
			w.log.Info("ownership inputs queued", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Handle is used by the existing durable queue loop, including its heartbeat,
// exponential retry and dead-letter protocol. No workspace or network is needed.
func (w *Worker) Handle(ctx context.Context, job ports.QueuedJob) error {
	if job.Kind != RouteJobKind || job.TenantID.IsZero() {
		return shared.ErrValidation
	}
	ctx = shared.WithTenant(ctx, job.TenantID)
	compiled := map[string]*domain.Resolver{}
	for {
		items, err := w.store.LoadOwnershipWork(ctx, job, 50)
		if err != nil {
			return err
		}
		if len(items) == 0 {
			return nil
		}
		for _, item := range items {
			if err := ctx.Err(); err != nil {
				return err
			}
			// An enforce job must remain pending when a deployment is paused in
			// observe mode. Completing it here would silently lose its obligation.
			if item.Mode != "preview" && item.Mode != "observe" && w.mode != "enforce" {
				return ports.ErrRetryable
			}
			key := fmt.Sprintf("%s:%d", item.PolicyID, item.PolicyVersion)
			resolver := compiled[key]
			if resolver == nil {
				policy, err := w.repo.GetPolicyVersion(ctx, item.PolicyID, item.PolicyVersion)
				if err != nil {
					return err
				}
				var snapshot *domain.Snapshot
				if !policy.SnapshotID.IsZero() {
					s, err := w.repo.GetSnapshot(ctx, policy.SnapshotID)
					if err != nil {
						return err
					}
					snapshot = &s
				}
				resolver, err = domain.NewResolver(policy, snapshot)
				if err != nil {
					return err
				}
				compiled[key] = resolver
			}
			result, err := resolver.Resolve(item.Input)
			if err != nil {
				return err
			}
			outcome := "evaluated"
			if result.Reason == "manual_protected" {
				outcome = "manual_protected"
			}
			err = w.store.CommitOwnershipWork(ctx, job, item, result, outcome, w.notify)
			if errors.Is(err, shared.ErrConflict) || errors.Is(err, shared.ErrNotFound) {
				// Record a stale preview/selection explicitly. Automatic inputs get
				// a fresh durable obligation; historical runs never silently refresh.
				err = w.store.CommitOwnershipWork(ctx, job, item, result, "conflict", false)
			}
			if err != nil {
				return err
			}
		}
	}
}

func (w *Worker) OnDeadLetter(ctx context.Context, job ports.QueuedJob, _ error) error {
	return w.store.FailOwnershipWork(shared.WithTenant(ctx, job.TenantID), job)
}

func (w *Worker) ReplayOwnershipRun(ctx context.Context, actor, run shared.ID, revision int) error {
	return w.store.ReplayOwnershipRun(ctx, actor, run, revision)
}
