package response

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// DefaultReconciliationInterval bounds how long a committed halt can wait for executor replay.
const DefaultReconciliationInterval = time.Minute

type TenantLister interface {
	ListTenantIDs(context.Context) ([]shared.ID, error)
}

type pendingReconciler interface {
	ReconcilePending(context.Context) error
}

type incidentLinkReconciler interface {
	ReconcileIncidentLinks(context.Context) error
}

// ReconciliationRunner repairs durable response obligations within each tenant's RLS context.
type ReconciliationRunner struct {
	tenants       TenantLister
	reconciler    pendingReconciler
	incidentLinks incidentLinkReconciler
	log           *slog.Logger
}

func NewReconciliationRunner(tenants TenantLister, reconciler pendingReconciler, log *slog.Logger, incidentLinks ...incidentLinkReconciler) (*ReconciliationRunner, error) {
	if tenants == nil || reconciler == nil || log == nil || len(incidentLinks) > 1 {
		return nil, fmt.Errorf("%w: response reconciliation runner dependencies are required", shared.ErrValidation)
	}
	var links incidentLinkReconciler
	if len(incidentLinks) == 1 {
		if incidentLinks[0] == nil {
			return nil, fmt.Errorf("%w: incident response link reconciler is required when configured", shared.ErrValidation)
		}
		links = incidentLinks[0]
	}
	return &ReconciliationRunner{tenants: tenants, reconciler: reconciler, incidentLinks: links, log: log}, nil
}

func (r *ReconciliationRunner) RunOnce(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tenants, err := r.tenants.ListTenantIDs(ctx)
	if err != nil {
		return fmt.Errorf("list response reconciliation tenants: %w", err)
	}
	var errs []error
	for _, tenantID := range tenants {
		if err := ctx.Err(); err != nil {
			return err
		}
		if tenantID.IsZero() {
			r.log.Error("response reconciliation tenant is invalid")
			errs = append(errs, fmt.Errorf("%w: response reconciliation tenant is invalid", shared.ErrValidation))
			continue
		}
		tenantCtx := shared.WithTenant(ctx, tenantID)
		if err := r.reconciler.ReconcilePending(tenantCtx); err != nil {
			r.log.Error("response reconciliation failed", "tenant", tenantID, "err", err)
			errs = append(errs, fmt.Errorf("reconcile tenant %s response obligations: %w", tenantID, err))
		}
		if r.incidentLinks != nil {
			if err := r.incidentLinks.ReconcileIncidentLinks(tenantCtx); err != nil {
				r.log.Error("incident response-link reconciliation failed", "tenant", tenantID, "err", err)
				errs = append(errs, fmt.Errorf("reconcile tenant %s incident response links: %w", tenantID, err))
			}
		}
	}
	return errors.Join(errs...)
}

func (r *ReconciliationRunner) RunPeriodic(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultReconciliationInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.RunOnce(ctx); err != nil && ctx.Err() == nil {
				r.log.Error("response reconciliation run failed", "err", err)
			}
		}
	}
}
