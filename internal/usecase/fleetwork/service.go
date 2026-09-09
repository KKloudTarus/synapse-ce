// Package fleetwork is the use-case layer for the fleet work order lifecycle (#407, epic #405):
// issue a signed, addressed, authorised order; let an agent claim orders addressed to it; and
// drive orders through the validated state machine. It audits every mutation and keeps the domain
// pure. The store enforces tenant isolation (RLS), idempotency and the in-flight uniqueness guard;
// this layer signs, validates transitions, and audits.
package fleetwork

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const workOrderLeaseTerm = 2 * time.Minute

// Service is the work order use case.
type Service struct {
	store  ports.WorkOrderAuditStore
	signer ports.WorkOrderSigner
	audit  ports.IdempotentAuditLogger
	clock  ports.Clock
	ids    ports.IDGenerator
	guard  ports.ExecutionAuthorizer
}

// SetExecutionAuthorizer installs the current-state guard used at the endpoint execution boundary.
func (s *Service) SetExecutionAuthorizer(guard ports.ExecutionAuthorizer) {
	s.guard = guard
}

// NewService validates its dependencies and returns the service.
func NewService(store ports.WorkOrderAuditStore, signer ports.WorkOrderSigner, audit ports.IdempotentAuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if store == nil || signer == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: fleetwork service needs store + signer + audit + clock + ids", shared.ErrValidation)
	}
	return &Service{store: store, signer: signer, audit: audit, clock: clock, ids: ids}, nil
}

// IssueInput remains an alias for compatibility; the issuance DTO lives in ports.
type IssueInput = ports.FleetWorkIssueInput

// Issue builds, signs and persists a work order. It is idempotent by (tenant, idempotency key):
// re-issuing returns the existing order. A second live order for the same
// (tenant, asset, capability, time bucket) is rejected by the store with shared.ErrConflict.
func (s *Service) Issue(ctx context.Context, actor string, in IssueInput) (*workorder.WorkOrder, error) {
	now := s.clock.Now()
	workOrderID := s.ids.NewID()
	if in.ResponseCommand != nil {
		workOrderID = in.ResponseCommand.CommandID
	} else if in.ResponseHalt != nil {
		workOrderID = in.ResponseHalt.CommandID
	} else if in.ResponseObserve != nil {
		workOrderID = in.ResponseObserve.RequestID
	}
	wo, err := workorder.New(workOrderID, in.TenantID, in.AssetID, in.AgentID, in.Capability,
		in.AuthorizationID, in.IdempotencyKey, in.NotAfter, in.TimeBucket, now)
	if err != nil {
		return nil, err
	}
	if in.ResponseCommand != nil {
		if err := wo.AttachResponseCommand(*in.ResponseCommand); err != nil {
			return nil, err
		}
	} else if in.ResponseHalt != nil {
		if err := wo.AttachResponseHaltCommand(*in.ResponseHalt); err != nil {
			return nil, err
		}
	} else if in.ResponseObserve != nil {
		if err := wo.AttachResponseObservation(*in.ResponseObserve); err != nil {
			return nil, err
		}
	} else if in.Capability == workorder.CapabilityResponseProcess || in.Capability == workorder.CapabilityResponseHalt ||
		in.Capability == workorder.CapabilityResponseObserve {
		return nil, fmt.Errorf("%w: response work order requires a signed response command", shared.ErrValidation)
	}
	wo.Signature = s.signer.Sign(wo.SigningPayload())
	ctx = shared.WithTenant(ctx, wo.TenantID)

	auditKey := "work_order.issued:v1:" + wo.TenantID.String() + ":" + wo.ID.String()
	intent := ports.FleetAuditIntent{ID: auditKey, Entry: ports.AuditEntry{
		Actor:  actor,
		Action: "work_order.issued",
		Target: wo.ID.String(),
		Metadata: map[string]string{
			"idempotency_key": auditKey,
			"tenant_id":       wo.TenantID.String(),
			"asset_id":        wo.AssetID.String(),
			"agent_id":        wo.AgentID.String(),
			"capability":      wo.Capability,
		},
		At: wo.Audit.CreatedAt,
	}}
	stored, committed, err := s.store.IssueWithAudit(ctx, wo, intent)
	if err != nil {
		return nil, fmt.Errorf("work order issue: %w", err)
	}
	if err := s.deliverAudit(ctx, committed); err != nil {
		return nil, fmt.Errorf("work order issue: audit: %w", err)
	}
	return stored, nil
}

// Verify reports whether the order's signature matches its current authorising fields. The agent
// runtime (a later issue) uses this before acting; exposed here so the signing contract is testable.
func (s *Service) Verify(wo *workorder.WorkOrder) bool {
	return s.signer.Verify(wo.SigningPayload(), wo.Signature)
}

// Claim atomically claims up to max unexpired orders addressed to agentID, moving them from issued
// to claimed, and audits each claim.
func (s *Service) Claim(ctx context.Context, actor string, tenantID, agentID shared.ID, max int) ([]*workorder.WorkOrder, error) {
	ctx = shared.WithTenant(ctx, tenantID)
	if max <= 0 {
		// Nothing to claim; return empty consistently rather than letting a negative LIMIT diverge
		// between the Postgres and memory stores.
		return nil, nil
	}
	now := s.clock.Now()
	leaseID := s.ids.NewID().String()
	if strings.TrimSpace(leaseID) == "" {
		return nil, fmt.Errorf("%w: work order claim requires a lease id", shared.ErrValidation)
	}
	claimed, intents, err := s.store.ClaimWithAudit(ctx, tenantID, agentID, max, now, leaseID, now.Add(workOrderLeaseTerm), actor)
	if err != nil {
		return nil, fmt.Errorf("work order claim: %w", err)
	}
	for _, intent := range intents {
		if err := s.audit.Record(ctx, intent.Entry); err != nil {
			return nil, fmt.Errorf("work order claim: audit: %w", err)
		}
		if err := s.store.AcknowledgeFleetAudit(ctx, intent.ID); err != nil {
			return nil, fmt.Errorf("work order claim: acknowledge audit: %w", err)
		}
	}
	return claimed, nil
}

// Transition moves an order to a new state after validating the transition is legal for its current
// state, using an optimistic expected-state check in the store. reason is required for a refusal.
func (s *Service) Transition(ctx context.Context, actor string, tenantID, id shared.ID, leaseID string, to workorder.State, reason string) error {
	ctx = shared.WithTenant(ctx, tenantID)
	now := s.clock.Now()
	current, err := s.store.GetByID(ctx, tenantID, id)
	if err != nil {
		return fmt.Errorf("work order transition: %w", err)
	}
	if !workorder.CanTransition(current.State, to) {
		return fmt.Errorf("%w: illegal work order transition %s -> %s", shared.ErrValidation, current.State, to)
	}
	if current.ResponseCommand != nil && (to == workorder.StateSucceeded || to == workorder.StateFailed) {
		return fmt.Errorf("%w: response work orders require a structured execution result", shared.ErrValidation)
	}
	if strings.TrimSpace(leaseID) == "" || current.LeaseID != leaseID || current.LeaseUntil.IsZero() {
		return fmt.Errorf("%w: work order transition requires its current lease", shared.ErrForbidden)
	}
	if to == workorder.StateRunning && !now.Before(current.NotAfter) {
		intent, err := s.store.TransitionLeasedWithAudit(ctx, tenantID, id, leaseID, workorder.StateExpired, "authorization expired before execution", current.State, now, actor)
		if err != nil {
			return fmt.Errorf("work order expire before execution: %w", err)
		}
		if err := s.deliverAuditRecord(ctx, intent); err != nil {
			return fmt.Errorf("work order expire before execution audit: %w", err)
		}
		return fmt.Errorf("%w: work order authorization expired before execution", shared.ErrForbidden)
	}
	if to == workorder.StateRunning && !now.Before(current.LeaseUntil) {
		return fmt.Errorf("%w: work order claim lease expired before execution", shared.ErrForbidden)
	}
	if to == workorder.StateRunning && current.ResponseCommand != nil {
		if s.guard == nil {
			return fmt.Errorf("%w: response execution authorization guard is unavailable", shared.ErrForbidden)
		}
		action := "response." + string(current.ResponseCommand.Action.Kind)
		if current.ResponseCommand.Reversal {
			action = "response." + string(current.ResponseCommand.Action.Reversal.Kind)
		}
		if _, err := s.guard.Authorize(ctx, ports.ExecutionRequest{
			Actor: actor, EngagementID: current.AuthorizationID, Action: action,
			Target: current.ResponseCommand.AuthorizationTarget,
			Metadata: map[string]string{
				"work_order_id": current.ID.String(), "attempt_key": current.ResponseCommand.AttemptKey,
			},
		}); err != nil {
			if !errors.Is(err, shared.ErrForbidden) {
				return fmt.Errorf("response execution authorization check: %w", err)
			}
			const refusalReason = "execution authorization denied"
			intent, transitionErr := s.store.TransitionLeasedWithAudit(ctx, tenantID, id, leaseID, workorder.StateRefused, refusalReason, current.State, now, actor)
			if transitionErr != nil {
				return fmt.Errorf("response execution authorization denied: %w", errors.Join(err, transitionErr))
			}
			if auditErr := s.deliverAuditRecord(ctx, intent); auditErr != nil {
				return fmt.Errorf("response execution authorization denied: %w", errors.Join(err, auditErr))
			}
			return fmt.Errorf("response execution authorization denied: %w", err)
		}
	}
	if to == workorder.StateRefused && reason == "" {
		return fmt.Errorf("%w: a refusal requires a reason", shared.ErrValidation)
	}
	intent, err := s.store.TransitionLeasedWithAudit(ctx, tenantID, id, leaseID, to, reason, current.State, now, actor)
	if err != nil {
		return fmt.Errorf("work order transition: %w", err)
	}
	if err := s.deliverAuditRecord(ctx, intent); err != nil {
		return fmt.Errorf("work order transition: audit: %w", err)
	}
	return nil
}

// CompleteResponse persists a lease-bound endpoint execution result and its terminal work-order
// state atomically. The result records application only; independent telemetry still verifies effect.
func (s *Service) CompleteResponse(ctx context.Context, actor string, tenantID, id shared.ID, result fleetagent.ResponseExecutionResult, reason string) error {
	ctx = shared.WithTenant(ctx, tenantID)
	now := s.clock.Now()
	changed, intent, err := s.store.CompleteResponseWithAudit(ctx, tenantID, id, result, reason, now, actor)
	if err != nil {
		return fmt.Errorf("complete response work order: %w", err)
	}
	if changed {
		if err := s.deliverAudit(ctx, intent); err != nil {
			return fmt.Errorf("complete response work order: audit: %w", err)
		}
		return nil
	}
	// An exact terminal retry may be repairing a prior delivery failure. The
	// mutation is already durable; replay only its persisted audit intention.
	key := fmt.Sprintf("work-order-response-completed:v1:%s:%s:%s", tenantID, id, result.AttemptKey)
	pending, err := s.store.ListPendingFleetAudits(ctx)
	if err != nil {
		return fmt.Errorf("complete response work order: list pending audit: %w", err)
	}
	for _, pendingIntent := range pending {
		if pendingIntent.ID == key {
			if err := s.deliverAudit(ctx, pendingIntent); err != nil {
				return fmt.Errorf("complete response work order: audit: %w", err)
			}
			break
		}
	}
	return nil
}

// GetByID returns the order or shared.ErrNotFound.
func (s *Service) GetByID(ctx context.Context, tenantID, id shared.ID) (*workorder.WorkOrder, error) {
	return s.store.GetByID(ctx, tenantID, id)
}

func (s *Service) GetByIdempotencyKey(ctx context.Context, tenantID shared.ID, idempotencyKey string) (*workorder.WorkOrder, error) {
	return s.store.GetByIdempotencyKey(ctx, tenantID, idempotencyKey)
}

// FenceResponses cancels every live effect command below a durable tenant halt generation.
func (s *Service) FenceResponses(ctx context.Context, actor string, tenantID shared.ID, generation int64, reason string) error {
	ctx = shared.WithTenant(ctx, tenantID)
	if generation <= 0 || strings.TrimSpace(reason) == "" {
		return fmt.Errorf("%w: response work-order fence requires generation and reason", shared.ErrValidation)
	}
	now := s.clock.Now().UTC()
	cancelled, intent, err := s.store.CancelResponsesBelowGenerationWithAudit(ctx, tenantID, generation, reason, now, actor)
	if err != nil {
		return fmt.Errorf("cancel response work orders below generation %d: %w", generation, err)
	}
	if err := s.deliverAuditRecord(ctx, intent); err != nil {
		return fmt.Errorf("audit response work-order fence: %w", err)
	}
	_ = cancelled
	return nil
}

func (s *Service) deliverAuditRecord(ctx context.Context, intent ports.FleetAuditIntent) error {
	if err := s.audit.Record(ctx, intent.Entry); err != nil {
		return err
	}
	return s.store.AcknowledgeFleetAudit(ctx, intent.ID)
}

func (s *Service) deliverAudit(ctx context.Context, intent ports.FleetAuditIntent) error {
	if err := s.audit.RecordOnce(ctx, intent.Entry); err != nil {
		return err
	}
	return s.store.AcknowledgeFleetAudit(ctx, intent.ID)
}
