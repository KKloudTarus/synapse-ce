package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fleetDesiredStoreKey struct {
	tenantID shared.ID
	assetID  shared.ID
}

// FleetDesiredStore is the in-memory desired-state store used by development and focused tests.
type FleetDesiredStore struct {
	mu     sync.RWMutex
	states map[fleetDesiredStoreKey]fleetdesired.State
}

var _ ports.FleetDesiredStore = (*FleetDesiredStore)(nil)

func NewFleetDesiredStore() *FleetDesiredStore {
	return &FleetDesiredStore{states: make(map[fleetDesiredStoreKey]fleetdesired.State)}
}

func cloneDesired(state fleetdesired.State) fleetdesired.State {
	state.Capabilities = append([]string(nil), state.Capabilities...)
	return state
}

func (s *FleetDesiredStore) Get(_ context.Context, tenantID, assetID shared.ID) (*fleetdesired.State, error) {
	if tenantID.IsZero() || assetID.IsZero() {
		return nil, fmt.Errorf("%w: desired-state lookup needs tenant and asset", shared.ErrValidation)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.states[fleetDesiredStoreKey{tenantID: tenantID, assetID: assetID}]
	if !ok {
		return nil, fmt.Errorf("desired state for asset %s: %w", assetID, shared.ErrNotFound)
	}
	state = cloneDesired(state)
	return &state, nil
}

// Put applies a lifecycle-aware CAS. A new PolicyID may only create an absent row at version 1;
// updates must retain the stored PolicyID and advance version by exactly one. PolicyID is unique
// within a tenant so a lifecycle identifier can never alias another asset's policy.
func (s *FleetDesiredStore) Put(_ context.Context, state *fleetdesired.State) error {
	if state == nil {
		return fmt.Errorf("%w: nil fleet desired state", shared.ErrValidation)
	}
	if err := state.Validate(); err != nil {
		return err
	}
	stored := cloneDesired(*state)
	key := fleetDesiredStoreKey{tenantID: state.TenantID, assetID: state.AssetID}

	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.states[key]
	if !exists {
		if stored.Version != 1 {
			return fmt.Errorf("%w: desired state for asset %s is absent; create requires version 1", shared.ErrConflict, state.AssetID)
		}
		for existingKey, existing := range s.states {
			if existingKey.tenantID == stored.TenantID && existing.PolicyID == stored.PolicyID {
				return fmt.Errorf("%w: desired policy id %s already belongs to asset %s in tenant %s",
					shared.ErrConflict, stored.PolicyID, existing.AssetID, stored.TenantID)
			}
		}
		s.states[key] = stored
		return nil
	}
	if stored.PolicyID != current.PolicyID {
		return fmt.Errorf("%w: desired policy lifecycle changed from %s to %s for asset %s",
			shared.ErrConflict, current.PolicyID, stored.PolicyID, state.AssetID)
	}
	if current.Version == 1<<63-1 {
		return fmt.Errorf("%w: desired state version exhausted for asset %s", shared.ErrConflict, state.AssetID)
	}
	if stored.Version != current.Version+1 {
		return fmt.Errorf("%w: desired state version %d does not follow stored version %d for asset %s",
			shared.ErrConflict, stored.Version, current.Version, state.AssetID)
	}
	stored.Audit.CreatedAt = current.Audit.CreatedAt
	if err := stored.Validate(); err != nil {
		return err
	}
	s.states[key] = stored
	return nil
}

// Delete clears only the lifecycle/version the caller observed. Absence is idempotent; either a newer
// version or a delete/recreate lifecycle returns ErrConflict and remains untouched.
func (s *FleetDesiredStore) Delete(_ context.Context, tenantID, assetID, expectedPolicyID shared.ID, expectedVersion int64) error {
	if tenantID.IsZero() || assetID.IsZero() || expectedPolicyID.IsZero() || expectedVersion < 1 {
		return fmt.Errorf("%w: desired-state delete needs tenant, asset, policy id and positive expected version", shared.ErrValidation)
	}
	key := fleetDesiredStoreKey{tenantID: tenantID, assetID: assetID}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.states[key]
	if !exists {
		return nil
	}
	if current.PolicyID != expectedPolicyID || current.Version != expectedVersion {
		return fmt.Errorf("%w: desired policy changed after %s@%d for asset %s",
			shared.ErrConflict, expectedPolicyID, expectedVersion, assetID)
	}
	delete(s.states, key)
	return nil
}

func (s *FleetDesiredStore) List(_ context.Context, tenantID shared.ID) ([]*fleetdesired.State, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: desired-state list needs a tenant", shared.ErrValidation)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*fleetdesired.State, 0)
	for _, state := range s.states {
		if state.TenantID != tenantID {
			continue
		}
		copy := cloneDesired(state)
		out = append(out, &copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AssetID < out[j].AssetID })
	return out, nil
}
