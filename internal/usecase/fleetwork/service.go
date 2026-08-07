// Package fleetwork is the use-case layer for the fleet work order lifecycle (#407, epic #405):
// issue a signed, addressed, authorised order; let an agent claim orders addressed to it; and
// drive orders through the validated state machine. It audits every mutation and keeps the domain
// pure. The store enforces tenant isolation (RLS), idempotency and the in-flight uniqueness guard;
// this layer signs, validates transitions, and audits.
package fleetwork

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service is the work order use case.
type Service struct {
	store  ports.WorkOrderStore
	signer ports.WorkOrderSigner
	audit  ports.AuditLogger
	clock  ports.Clock
	ids    ports.IDGenerator
}

// NewService validates its dependencies and returns the service.
func NewService(store ports.WorkOrderStore, signer ports.WorkOrderSigner, audit ports.AuditLogger, clock ports.Clock, ids ports.IDGenerator) (*Service, error) {
	if store == nil || signer == nil || audit == nil || clock == nil || ids == nil {
		return nil, fmt.Errorf("%w: fleetwork service needs store + signer + audit + clock + ids", shared.ErrValidation)
	}
	return &Service{store: store, signer: signer, audit: audit, clock: clock, ids: ids}, nil
}

// IssueInput describes a work order to issue. TenantID must be non-empty (empty is DENY under RLS).
type IssueInput struct {
	TenantID        shared.ID
	AssetID         shared.ID
	AgentID         shared.ID
	Capability      string
	AuthorizationID shared.ID
	IdempotencyKey  string
	NotAfter        time.Time
	TimeBucket      int64
}

// Issue builds, signs and persists a work order. It is idempotent by (tenant, idempotency key):
// re-issuing returns the existing order. A second live order for the same
// (tenant, asset, capability, time bucket) is rejected by the store with shared.ErrConflict.
func (s *Service) Issue(ctx context.Context, actor string, in IssueInput) (*workorder.WorkOrder, error) {
	now := s.clock.Now()
	wo, err := workorder.New(s.ids.NewID(), in.TenantID, in.AssetID, in.AgentID, in.Capability,
		in.AuthorizationID, in.IdempotencyKey, in.NotAfter, in.TimeBucket, now)
	if err != nil {
		return nil, err
	}
	wo.Signature = s.signer.Sign(wo.SigningPayload())

	stored, err := s.store.Issue(ctx, wo)
	if err != nil {
		return nil, fmt.Errorf("work order issue: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:  actor,
		Action: "work_order.issued",
		Target: stored.ID.String(),
		Metadata: map[string]string{
			"tenant_id":  stored.TenantID.String(),
			"asset_id":   stored.AssetID.String(),
			"agent_id":   stored.AgentID.String(),
			"capability": stored.Capability,
		},
		At: now,
	}); err != nil {
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
	if max <= 0 {
		// Nothing to claim; return empty consistently rather than letting a negative LIMIT diverge
		// between the Postgres and memory stores.
		return nil, nil
	}
	now := s.clock.Now()
	claimed, err := s.store.Claim(ctx, tenantID, agentID, max, now)
	if err != nil {
		return nil, fmt.Errorf("work order claim: %w", err)
	}
	for _, wo := range claimed {
		if err := s.audit.Record(ctx, ports.AuditEntry{
			Actor:  actor,
			Action: "work_order.claimed",
			Target: wo.ID.String(),
			Metadata: map[string]string{
				"tenant_id": wo.TenantID.String(),
				"agent_id":  wo.AgentID.String(),
			},
			At: now,
		}); err != nil {
			return nil, fmt.Errorf("work order claim: audit: %w", err)
		}
	}
	return claimed, nil
}

// Transition moves an order to a new state after validating the transition is legal for its current
// state, using an optimistic expected-state check in the store. reason is required for a refusal.
func (s *Service) Transition(ctx context.Context, actor string, tenantID, id shared.ID, to workorder.State, reason string) error {
	now := s.clock.Now()
	current, err := s.store.GetByID(ctx, tenantID, id)
	if err != nil {
		return fmt.Errorf("work order transition: %w", err)
	}
	if !workorder.CanTransition(current.State, to) {
		return fmt.Errorf("%w: illegal work order transition %s -> %s", shared.ErrValidation, current.State, to)
	}
	if to == workorder.StateRefused && reason == "" {
		return fmt.Errorf("%w: a refusal requires a reason", shared.ErrValidation)
	}
	if err := s.store.Transition(ctx, tenantID, id, to, reason, current.State, now); err != nil {
		return fmt.Errorf("work order transition: %w", err)
	}
	if err := s.audit.Record(ctx, ports.AuditEntry{
		Actor:  actor,
		Action: "work_order.transitioned",
		Target: id.String(),
		Metadata: map[string]string{
			"tenant_id": tenantID.String(),
			"from":      string(current.State),
			"to":        string(to),
			"reason":    reason,
		},
		At: now,
	}); err != nil {
		return fmt.Errorf("work order transition: audit: %w", err)
	}
	return nil
}

// GetByID returns the order or shared.ErrNotFound.
func (s *Service) GetByID(ctx context.Context, tenantID, id shared.ID) (*workorder.WorkOrder, error) {
	return s.store.GetByID(ctx, tenantID, id)
}
