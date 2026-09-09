package response

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func responseAuditIntent(id, actor, action, target string, at time.Time, metadata map[string]string) ports.ResponseAuditIntent {
	metadata = maps.Clone(metadata)
	metadata["idempotency_key"] = id
	return ports.ResponseAuditIntent{ID: id, Entry: ports.AuditEntry{Actor: actor, Action: action, Target: target, At: at, Metadata: metadata}}
}

func (s *Service) deliverResponseAudit(ctx context.Context, intent ports.ResponseAuditIntent) error {
	if err := s.audit.RecordOnce(ctx, intent.Entry); err != nil {
		return err
	}
	return s.store.AcknowledgeResponseAudit(ctx, intent.ID)
}

func (s *Service) deliverHaltDispatch(ctx context.Context, dispatch ports.ResponseHaltDispatch) error {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || tenantID.IsZero() || dispatch.TenantID != tenantID || dispatch.Generation <= 0 {
		return fmt.Errorf("%w: response halt dispatch is not bound to the current tenant", shared.ErrForbidden)
	}
	if err := s.exec.Halt(ctx, dispatch.TenantID, dispatch.Generation); err != nil {
		return err
	}
	return s.store.AcknowledgeResponseHaltDispatch(ctx, dispatch.Generation)
}

// ReconcileHaltDispatches replays durable executor fences left by a crash or transient executor outage.
// Executor.Halt is monotonic by contract, so duplicate or older-generation delivery cannot lower a fence.
func (s *Service) ReconcileHaltDispatches(ctx context.Context) error {
	pending, err := s.store.ListPendingResponseHaltDispatches(ctx)
	if err != nil {
		return fmt.Errorf("list pending response halt dispatches: %w", err)
	}
	var errs []error
	for _, dispatch := range pending {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		deliveryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := s.deliverHaltDispatch(deliveryCtx, dispatch)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("deliver response halt generation %d: %w", dispatch.Generation, err))
		}
	}
	return errors.Join(errs...)
}

// ReconcileAudits idempotently drains response audit obligations left by a crash or audit outage.
func (s *Service) ReconcileAudits(ctx context.Context) error {
	pending, err := s.store.ListPendingResponseAudits(ctx)
	if err != nil {
		return fmt.Errorf("list pending response audits: %w", err)
	}
	var errs []error
	for _, intent := range pending {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		if err := s.deliverResponseAudit(ctx, intent); err != nil {
			errs = append(errs, fmt.Errorf("deliver response audit %s: %w", intent.ID, err))
		}
	}
	return errors.Join(errs...)
}
