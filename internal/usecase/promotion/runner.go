package promotion

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ReconciliationRunner invokes a reconciler for every discovered tenant-bound engagement.
type ReconciliationRunner struct {
	scopes     ports.PromotionReconciliationScopeReader
	evaluator  ports.PromotionEvaluator
	reconciler ports.PromotionReconciler
	governance ports.GovernanceReconciler
	log        *slog.Logger
}

func NewReconciliationRunner(scopes ports.PromotionReconciliationScopeReader, evaluator ports.PromotionEvaluator, reconciler ports.PromotionReconciler, log *slog.Logger) (*ReconciliationRunner, error) {
	if scopes == nil || evaluator == nil || reconciler == nil || log == nil {
		return nil, fmt.Errorf("%w: promotion reconciliation runner is missing a dependency", shared.ErrValidation)
	}
	return &ReconciliationRunner{scopes: scopes, evaluator: evaluator, reconciler: reconciler, log: log}, nil
}

// SetGovernanceReconciler adds server-only durable governance recovery without
// granting the evaluator or any read path mutation authority.
func (r *ReconciliationRunner) SetGovernanceReconciler(governance ports.GovernanceReconciler) {
	r.governance = governance
}

// RunOnce reconciles every scope. Per-scope failures are logged and do not block
// other tenants; scope discovery and cancellation failures are returned.
func (r *ReconciliationRunner) RunOnce(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	scopes, err := r.scopes.ListPromotionReconciliationScopes(ctx)
	if err != nil {
		return fmt.Errorf("list promotion reconciliation scopes: %w", err)
	}
	for _, scope := range scopes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if scope.TenantID.IsZero() || scope.EngagementID.IsZero() {
			r.log.Error("promotion reconciliation scope is invalid", "tenant", scope.TenantID, "engagement", scope.EngagementID)
			continue
		}
		scopeCtx := shared.WithTenant(ctx, scope.TenantID)
		// A confirmed promotion can only be applied after its verdict audit outbox is
		// delivered. Do this recovery first and skip the mutating reconciler on failure.
		if r.governance != nil {
			if err := r.governance.Reconcile(scopeCtx, scope.EngagementID); err != nil {
				r.log.Error("governance reconciliation failed", "tenant", scope.TenantID, "engagement", scope.EngagementID, "err", err)
				continue
			}
		}
		if _, err := r.evaluator.Evaluate(scopeCtx, scope.EngagementID); err != nil {
			r.log.Error("promotion evaluation failed", "tenant", scope.TenantID, "engagement", scope.EngagementID, "err", err)
		}
		if err := r.reconciler.Reconcile(scopeCtx, scope.EngagementID); err != nil {
			r.log.Error("promotion reconciliation failed", "tenant", scope.TenantID, "engagement", scope.EngagementID, "err", err)
		}
	}
	return nil
}

// RunPeriodic reconciles at interval until ctx is cancelled.
func (r *ReconciliationRunner) RunPeriodic(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.RunOnce(ctx); err != nil && ctx.Err() == nil {
				r.log.Error("promotion reconciliation run failed", "err", err)
			}
		}
	}
}
