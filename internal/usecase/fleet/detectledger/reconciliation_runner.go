package detectledger

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ReconciliationRunner repairs pending attributed detections within each tenant boundary.
type ReconciliationRunner struct {
	tenants    ports.DetectionReconciliationTenantStore
	reconciler ports.PendingDetectionReconciler
	log        *slog.Logger
}

func NewReconciliationRunner(
	tenants ports.DetectionReconciliationTenantStore,
	reconciler ports.PendingDetectionReconciler,
	log *slog.Logger,
) (*ReconciliationRunner, error) {
	if tenants == nil || reconciler == nil || log == nil {
		return nil, fmt.Errorf("%w: detection reconciliation runner is missing a dependency", shared.ErrValidation)
	}
	return &ReconciliationRunner{tenants: tenants, reconciler: reconciler, log: log}, nil
}

// RunOnce enumerates tenant scopes globally, then rebinds every repair call to its tenant.
func (r *ReconciliationRunner) RunOnce(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tenantIDs, err := r.tenants.ListTenantIDs(ctx)
	if err != nil {
		return fmt.Errorf("list detection reconciliation tenants: %w", err)
	}
	for _, tenantID := range tenantIDs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if tenantID.IsZero() {
			r.log.Error("detection reconciliation tenant is invalid")
			continue
		}
		tenantCtx := shared.WithTenant(ctx, tenantID)
		completed, err := r.reconciler.ReconcilePendingDetections(tenantCtx)
		if err != nil {
			r.log.Error("detection reconciliation failed", "tenant", tenantID, "err", err)
			continue
		}
		if completed > 0 {
			r.log.Info("pending detections reconciled", "tenant", tenantID, "count", completed)
		}
	}
	return nil
}

// RunPeriodic keeps repair bounded by process cancellation and uses a safe default interval.
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
				r.log.Error("detection reconciliation run failed", "err", err)
			}
		}
	}
}
