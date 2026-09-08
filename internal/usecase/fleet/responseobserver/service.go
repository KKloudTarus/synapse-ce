// Package responseobserver governs secondary agents that may observe response post-conditions.
package responseobserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const MaxBindingLifetime = 24 * time.Hour

type Service struct {
	store    ports.ResponseObserverBindingAuditStore
	agents   ports.FleetAgentStore
	bindings ports.TelemetryAssetBindingLister
	audit    ports.IdempotentAuditLogger
	clock    ports.Clock
}

type AssignInput struct {
	TenantID        shared.ID
	AgentID         shared.ID
	AssetID         shared.ID
	Actor           string
	ExpiresAt       time.Time
	ExpectedVersion int
}

func NewService(store ports.ResponseObserverBindingAuditStore, agents ports.FleetAgentStore, bindings ports.TelemetryAssetBindingLister, audit ports.IdempotentAuditLogger, clock ports.Clock) (*Service, error) {
	if store == nil || agents == nil || bindings == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: response-observer service is missing a dependency", shared.ErrValidation)
	}
	return &Service{store: store, agents: agents, bindings: bindings, audit: audit, clock: clock}, nil
}

// Assign authorizes one independently enrolled agent to observe a canonical asset. The assignment is
// operator-owned and cannot be inferred from agent-supplied heartbeat or inventory fields.
func (s *Service) Assign(ctx context.Context, input AssignInput) (fleetagent.ResponseObserverBinding, error) {
	now := s.clock.Now().UTC().Truncate(time.Microsecond)
	input.Actor = strings.TrimSpace(input.Actor)
	input.ExpiresAt = input.ExpiresAt.UTC().Truncate(time.Microsecond)
	if input.TenantID.IsZero() || input.AgentID.IsZero() || input.AssetID.IsZero() || input.Actor == "" ||
		shared.IsMachineActor(input.Actor) || input.ExpectedVersion < 0 || !now.Before(input.ExpiresAt) ||
		input.ExpiresAt.Sub(now) > MaxBindingLifetime {
		return fleetagent.ResponseObserverBinding{}, fmt.Errorf("%w: response-observer assignment requires a human, expected version, and expiry within %s", shared.ErrValidation, MaxBindingLifetime)
	}
	if tenantID, ok := shared.TenantFrom(ctx); !ok || tenantID != input.TenantID {
		return fleetagent.ResponseObserverBinding{}, fmt.Errorf("%w: response-observer assignment tenant disagrees with context", shared.ErrForbidden)
	}
	agent, err := s.agents.GetAgent(ctx, input.TenantID, input.AgentID)
	if err != nil {
		return fleetagent.ResponseObserverBinding{}, fmt.Errorf("read response observer agent: %w", err)
	}
	if agent.State != fleetagent.StateActive || !hasCapability(agent.Capabilities, workorder.CapabilityResponseObserve) {
		return fleetagent.ResponseObserverBinding{}, fmt.Errorf("%w: response observer must be active and advertise %s", shared.ErrForbidden, workorder.CapabilityResponseObserve)
	}
	primaryBindings, err := s.bindings.ListTelemetryAssetBindings(ctx)
	if err != nil {
		return fleetagent.ResponseObserverBinding{}, fmt.Errorf("list primary telemetry asset bindings: %w", err)
	}
	primaryFound := false
	for _, binding := range primaryBindings {
		if binding.TenantID != input.TenantID || binding.AssetID != input.AssetID {
			continue
		}
		primaryFound = true
		if binding.AgentID == input.AgentID {
			return fleetagent.ResponseObserverBinding{}, fmt.Errorf("%w: an asset's primary agent cannot be its independent response observer", shared.ErrForbidden)
		}
	}
	if !primaryFound {
		return fleetagent.ResponseObserverBinding{}, fmt.Errorf("%w: response observer target asset has no primary telemetry owner", shared.ErrNotFound)
	}
	binding := fleetagent.ResponseObserverBinding{
		TenantID: input.TenantID, AgentID: input.AgentID, AssetID: input.AssetID, AssignedBy: input.Actor,
		AssignedAt: now, ExpiresAt: input.ExpiresAt, Version: input.ExpectedVersion + 1,
	}
	intentID := fmt.Sprintf("fleet.response_observer.assigned:v1:%s:%d", input.AgentID, binding.Version)
	intent := ports.FleetAuditIntent{ID: intentID, Entry: ports.AuditEntry{
		Actor: input.Actor, Action: "fleet.response_observer.assigned", Target: input.AgentID.String(), At: now,
		Metadata: map[string]string{
			"idempotency_key": intentID, "agent_id": input.AgentID.String(), "asset_id": input.AssetID.String(),
			"expires_at": input.ExpiresAt.Format(time.RFC3339Nano), "version": fmt.Sprint(binding.Version),
		},
	}}
	binding, committed, err := s.store.SaveResponseObserverBindingWithAudit(ctx, binding, input.ExpectedVersion, intent)
	if err != nil {
		return fleetagent.ResponseObserverBinding{}, fmt.Errorf("persist response-observer assignment: %w", err)
	}
	if err := s.audit.RecordOnce(ctx, committed.Entry); err != nil {
		return fleetagent.ResponseObserverBinding{}, fmt.Errorf("audit response-observer assignment: %w", err)
	}
	if err := s.store.AcknowledgeFleetAudit(ctx, committed.ID); err != nil {
		return fleetagent.ResponseObserverBinding{}, fmt.Errorf("acknowledge response-observer assignment audit: %w", err)
	}
	return binding, nil
}

func hasCapability(capabilities []string, want string) bool {
	for _, capability := range capabilities {
		if strings.TrimSpace(capability) == want {
			return true
		}
	}
	return false
}
