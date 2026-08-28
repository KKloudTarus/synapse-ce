package fleetaudit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Reconciler delivers durable fleet audit intentions to the append-only audit
// chain and only then acknowledges their completion.
type Reconciler struct {
	stores []ports.FleetAuditIntentStore
	audit  ports.IdempotentAuditLogger
}

func NewReconciler(
	stores []ports.FleetAuditIntentStore,
	audit ports.IdempotentAuditLogger,
) (*Reconciler, error) {
	if len(stores) == 0 || audit == nil {
		return nil, fmt.Errorf("%w: fleet audit reconciler dependencies are required", shared.ErrValidation)
	}
	for _, store := range stores {
		if store == nil {
			return nil, fmt.Errorf("%w: fleet audit reconciler store is required", shared.ErrValidation)
		}
	}
	return &Reconciler{stores: append([]ports.FleetAuditIntentStore(nil), stores...), audit: audit}, nil
}

func (r *Reconciler) Reconcile(ctx context.Context) error {
	var errs []error
	for _, store := range r.stores {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		pending, err := store.ListPendingFleetAudits(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("list pending fleet audits: %w", err))
			continue
		}
		for _, intent := range pending {
			if err := ctx.Err(); err != nil {
				return errors.Join(append(errs, err)...)
			}
			if intent.ID == "" {
				errs = append(errs, fmt.Errorf("%w: pending fleet audit id is empty", shared.ErrValidation))
				continue
			}
			if err := r.audit.RecordOnce(ctx, intent.Entry); err != nil {
				errs = append(errs, fmt.Errorf("record pending fleet audit %s: %w", intent.ID, err))
				continue
			}
			if err := store.AcknowledgeFleetAudit(ctx, intent.ID); err != nil {
				errs = append(errs, fmt.Errorf("acknowledge pending fleet audit %s: %w", intent.ID, err))
			}
		}
	}
	return errors.Join(errs...)
}

type TenantLister interface {
	ListTenantIDs(context.Context) ([]shared.ID, error)
}

// DefaultInterval bounds how long a committed-but-undelivered audit intention can
// stay invisible in the audit chain after a crash between commit and delivery.
const DefaultInterval = time.Minute

type ReconciliationRunner struct {
	tenants    TenantLister
	reconciler *Reconciler
	log        *slog.Logger
}

func NewReconciliationRunner(
	tenants TenantLister,
	reconciler *Reconciler,
	log *slog.Logger,
) (*ReconciliationRunner, error) {
	if tenants == nil || reconciler == nil || log == nil {
		return nil, fmt.Errorf("%w: fleet audit reconciliation runner dependencies are required", shared.ErrValidation)
	}
	return &ReconciliationRunner{tenants: tenants, reconciler: reconciler, log: log}, nil
}

func (r *ReconciliationRunner) RunOnce(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tenants, err := r.tenants.ListTenantIDs(ctx)
	if err != nil {
		return fmt.Errorf("list fleet audit reconciliation tenants: %w", err)
	}
	for _, tenantID := range tenants {
		if err := ctx.Err(); err != nil {
			return err
		}
		if tenantID.IsZero() {
			r.log.Error("fleet audit reconciliation tenant is invalid")
			continue
		}
		if err := r.reconciler.Reconcile(shared.WithTenant(ctx, tenantID)); err != nil {
			r.log.Error("fleet audit reconciliation failed", "tenant", tenantID, "err", err)
		}
	}
	return nil
}

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
				r.log.Error("fleet audit reconciliation run failed", "err", err)
			}
		}
	}
}
