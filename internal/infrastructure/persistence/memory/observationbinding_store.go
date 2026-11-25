package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/observationbinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ObservationBindingStore is the in-memory conformance adapter for approved observation-to-finding
// bindings. One mutex serializes writes, which is what stands in for the partial unique index the
// PostgreSQL adapter relies on: two concurrent adopters still end with one binding and one conflict.
//
// It holds no foreign keys, so it cannot refuse a binding that points at a finding from another
// engagement. PostgreSQL does that with composite keys that carry the tenant and the engagement. Tests
// that assert cross-tenant reference protection belong against that adapter.
type ObservationBindingStore struct {
	mu       sync.RWMutex
	byTenant map[shared.ID][]observationbinding.Binding
}

var _ ports.ObservationBindingStore = (*ObservationBindingStore)(nil)

// NewObservationBindingStore returns an empty binding store.
func NewObservationBindingStore() *ObservationBindingStore {
	return &ObservationBindingStore{byTenant: map[shared.ID][]observationbinding.Binding{}}
}

// Adopt records the first binding for a scoped identity, idempotently for the same finding.
func (s *ObservationBindingStore) Adopt(_ context.Context, tenantID shared.ID, binding observationbinding.Binding) (observationbinding.Binding, error) {
	if err := validateMemoryBindingWrite(tenantID, binding); err != nil {
		return observationbinding.Binding{}, err
	}
	if binding.Version != 1 {
		return observationbinding.Binding{}, fmt.Errorf("%w: an adopted binding starts at version 1", shared.ErrValidation)
	}
	if !binding.SupersededAt.IsZero() {
		return observationbinding.Binding{}, fmt.Errorf("%w: an adopted binding cannot already be superseded", shared.ErrValidation)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if current, index := s.current(tenantID, binding.EngagementID, binding.Key()); index >= 0 {
		if current.FindingID == binding.FindingID {
			return current, nil
		}
		return observationbinding.Binding{}, fmt.Errorf("%w: observation %s/%s is already bound to finding %s",
			shared.ErrConflict, binding.Scope, binding.ExternalIdentity, current.FindingID)
	}
	s.byTenant[tenantID] = append(s.byTenant[tenantID], binding)
	return binding, nil
}

// Supersede retires the binding in force and records its replacement.
func (s *ObservationBindingStore) Supersede(_ context.Context, tenantID shared.ID, expectedVersion int, binding observationbinding.Binding) (observationbinding.Binding, error) {
	if err := validateMemoryBindingWrite(tenantID, binding); err != nil {
		return observationbinding.Binding{}, err
	}
	if expectedVersion < 1 {
		return observationbinding.Binding{}, fmt.Errorf("%w: superseding needs the version being replaced", shared.ErrValidation)
	}
	if binding.Version != expectedVersion+1 {
		return observationbinding.Binding{}, fmt.Errorf("%w: a superseding binding is one version after the one it replaces", shared.ErrValidation)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	current, index := s.current(tenantID, binding.EngagementID, binding.Key())
	if index < 0 {
		return observationbinding.Binding{}, shared.ErrNotFound
	}
	if current.Version != expectedVersion {
		return observationbinding.Binding{}, fmt.Errorf("%w: observation binding is at version %d, not %d",
			shared.ErrConflict, current.Version, expectedVersion)
	}
	s.byTenant[tenantID][index].SupersededAt = binding.DecidedAt
	s.byTenant[tenantID] = append(s.byTenant[tenantID], binding)
	return binding, nil
}

// Current returns the binding in force for a scoped identity.
func (s *ObservationBindingStore) Current(_ context.Context, tenantID, engagementID shared.ID, identity observationbinding.Identity) (observationbinding.Binding, error) {
	if tenantID.IsZero() || engagementID.IsZero() {
		return observationbinding.Binding{}, fmt.Errorf("%w: an observation binding read needs a tenant and an engagement", shared.ErrValidation)
	}
	if err := identity.Validate(); err != nil {
		return observationbinding.Binding{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if binding, index := s.current(tenantID, engagementID, identity); index >= 0 {
		return binding, nil
	}
	return observationbinding.Binding{}, shared.ErrNotFound
}

// CurrentByEngagement returns only the bindings in force.
func (s *ObservationBindingStore) CurrentByEngagement(_ context.Context, tenantID, engagementID shared.ID) ([]observationbinding.Binding, error) {
	if tenantID.IsZero() || engagementID.IsZero() {
		return nil, fmt.Errorf("%w: an observation binding listing needs a tenant and an engagement", shared.ErrValidation)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []observationbinding.Binding
	for _, binding := range s.byTenant[tenantID] {
		if binding.EngagementID == engagementID && binding.Current() {
			out = append(out, binding)
		}
	}
	return out, nil
}

// ListByEngagement returns every version in the engagement, newest decision first.
func (s *ObservationBindingStore) ListByEngagement(_ context.Context, tenantID, engagementID shared.ID) ([]observationbinding.Binding, error) {
	if tenantID.IsZero() || engagementID.IsZero() {
		return nil, fmt.Errorf("%w: an observation binding listing needs a tenant and an engagement", shared.ErrValidation)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []observationbinding.Binding
	for _, binding := range s.byTenant[tenantID] {
		if binding.EngagementID == engagementID {
			out = append(out, binding)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].DecidedAt.Equal(out[j].DecidedAt) {
			return out[i].DecidedAt.After(out[j].DecidedAt)
		}
		return out[i].Version > out[j].Version
	})
	return out, nil
}

// current returns the version in force and its index, or index -1.
func (s *ObservationBindingStore) current(tenantID, engagementID shared.ID, identity observationbinding.Identity) (observationbinding.Binding, int) {
	for index, binding := range s.byTenant[tenantID] {
		if binding.EngagementID == engagementID && binding.Key() == identity && binding.Current() {
			return binding, index
		}
	}
	return observationbinding.Binding{}, -1
}

func validateMemoryBindingWrite(tenantID shared.ID, binding observationbinding.Binding) error {
	if tenantID.IsZero() {
		return fmt.Errorf("%w: an observation binding write needs a tenant", shared.ErrValidation)
	}
	if binding.TenantID != tenantID {
		return fmt.Errorf("%w: observation binding %s is stamped with tenant %q but was written into %q",
			shared.ErrValidation, binding.ID, binding.TenantID, tenantID)
	}
	return binding.Validate()
}
