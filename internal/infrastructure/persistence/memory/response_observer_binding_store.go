package memory

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type ResponseObserverBindingStore struct {
	mu            sync.Mutex
	bindings      map[shared.ID]map[shared.ID]fleetagent.ResponseObserverBinding
	auditIntents  map[fleetAuditKey]ports.FleetAuditIntent
	auditComplete map[fleetAuditKey]bool
}

var _ ports.ResponseObserverBindingAuditStore = (*ResponseObserverBindingStore)(nil)

func NewResponseObserverBindingStore() *ResponseObserverBindingStore {
	return &ResponseObserverBindingStore{
		bindings:     map[shared.ID]map[shared.ID]fleetagent.ResponseObserverBinding{},
		auditIntents: map[fleetAuditKey]ports.FleetAuditIntent{}, auditComplete: map[fleetAuditKey]bool{},
	}
}

func (s *ResponseObserverBindingStore) SaveResponseObserverBindingWithAudit(ctx context.Context, binding fleetagent.ResponseObserverBinding, expectedVersion int, intent ports.FleetAuditIntent) (fleetagent.ResponseObserverBinding, ports.FleetAuditIntent, error) {
	tenantID, err := requireTelemetryTenant(ctx)
	if err != nil {
		return fleetagent.ResponseObserverBinding{}, ports.FleetAuditIntent{}, err
	}
	if err := binding.Validate(); err != nil {
		return fleetagent.ResponseObserverBinding{}, ports.FleetAuditIntent{}, err
	}
	if binding.TenantID != tenantID || expectedVersion < 0 || binding.Version != expectedVersion+1 {
		return fleetagent.ResponseObserverBinding{}, ports.FleetAuditIntent{}, shared.ErrValidation
	}
	intent, err = intent.Normalize()
	if err != nil {
		return fleetagent.ResponseObserverBinding{}, ports.FleetAuditIntent{}, err
	}
	auditKey := fleetAuditKey{tenant: tenantID, id: intent.ID}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, found := s.bindings[tenantID][binding.AgentID]
	if found && existing.Version == expectedVersion+1 && sameResponseObserverBindingRequest(existing, binding) {
		binding = existing
		intent.Entry.At = existing.AssignedAt
		if committed, exists := s.auditIntents[auditKey]; exists {
			if !ports.SameFleetAuditIntent(committed, intent) {
				return fleetagent.ResponseObserverBinding{}, ports.FleetAuditIntent{}, shared.ErrConflict
			}
			return existing, cloneMemoryFleetAuditIntent(committed), nil
		}
	}
	currentVersion := 0
	if found {
		currentVersion = existing.Version
	}
	if currentVersion != expectedVersion {
		return fleetagent.ResponseObserverBinding{}, ports.FleetAuditIntent{}, shared.ErrConflict
	}
	if committed, exists := s.auditIntents[auditKey]; exists && !ports.SameFleetAuditIntent(committed, intent) {
		return fleetagent.ResponseObserverBinding{}, ports.FleetAuditIntent{}, shared.ErrConflict
	}
	if s.bindings[tenantID] == nil {
		s.bindings[tenantID] = map[shared.ID]fleetagent.ResponseObserverBinding{}
	}
	s.bindings[tenantID][binding.AgentID] = binding
	s.auditIntents[auditKey] = cloneMemoryFleetAuditIntent(intent)
	return binding, cloneMemoryFleetAuditIntent(intent), nil
}

func (s *ResponseObserverBindingStore) GetResponseObserverBinding(ctx context.Context, agentID shared.ID) (fleetagent.ResponseObserverBinding, error) {
	tenantID, err := requireTelemetryTenant(ctx)
	if err != nil {
		return fleetagent.ResponseObserverBinding{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	binding, found := s.bindings[tenantID][agentID]
	if !found {
		return fleetagent.ResponseObserverBinding{}, shared.ErrNotFound
	}
	return binding, nil
}

func (s *ResponseObserverBindingStore) ListResponseObserverBindings(ctx context.Context, assetID shared.ID) ([]fleetagent.ResponseObserverBinding, error) {
	tenantID, err := requireTelemetryTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]fleetagent.ResponseObserverBinding, 0)
	for _, binding := range s.bindings[tenantID] {
		if binding.AssetID == assetID {
			out = append(out, binding)
		}
	}
	slices.SortFunc(out, func(left, right fleetagent.ResponseObserverBinding) int {
		return strings.Compare(left.AgentID.String(), right.AgentID.String())
	})
	return out, nil
}

func (s *ResponseObserverBindingStore) ListPendingFleetAudits(ctx context.Context) ([]ports.FleetAuditIntent, error) {
	tenantID, err := requireTelemetryTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ports.FleetAuditIntent, 0)
	for key, intent := range s.auditIntents {
		if key.tenant == tenantID && !s.auditComplete[key] {
			out = append(out, cloneMemoryFleetAuditIntent(intent))
		}
	}
	slices.SortFunc(out, func(left, right ports.FleetAuditIntent) int {
		if order := left.Entry.At.Compare(right.Entry.At); order != 0 {
			return order
		}
		return strings.Compare(left.ID, right.ID)
	})
	return out, nil
}

func (s *ResponseObserverBindingStore) AcknowledgeFleetAudit(ctx context.Context, id string) error {
	tenantID, err := requireTelemetryTenant(ctx)
	if err != nil {
		return err
	}
	key := fleetAuditKey{tenant: tenantID, id: strings.TrimSpace(id)}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, found := s.auditIntents[key]; !found {
		return fmt.Errorf("%w: response-observer audit intention", shared.ErrNotFound)
	}
	s.auditComplete[key] = true
	return nil
}

func sameResponseObserverBindingRequest(left, right fleetagent.ResponseObserverBinding) bool {
	return left.TenantID == right.TenantID && left.AgentID == right.AgentID && left.AssetID == right.AssetID &&
		left.AssignedBy == right.AssignedBy && left.ExpiresAt.Equal(right.ExpiresAt) && left.Version == right.Version
}
