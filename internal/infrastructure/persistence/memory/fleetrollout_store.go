package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetrollout"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// FleetRolloutStore is the in-memory rollout plan store.
type FleetRolloutStore struct {
	mu    sync.RWMutex
	plans map[string]fleetrollout.Plan
}

var _ ports.FleetRolloutStore = (*FleetRolloutStore)(nil)

// NewFleetRolloutStore returns an empty store.
func NewFleetRolloutStore() *FleetRolloutStore {
	return &FleetRolloutStore{plans: map[string]fleetrollout.Plan{}}
}

func rolloutKey(tenantID shared.ID, channel string) string {
	return tenantID.String() + "\x00" + fleetrollout.NormalizeChannel(channel)
}

// Get returns the plan, or shared.ErrNotFound when none is configured.
func (s *FleetRolloutStore) Get(_ context.Context, tenantID shared.ID, channel string) (*fleetrollout.Plan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	plan, ok := s.plans[rolloutKey(tenantID, channel)]
	if !ok {
		return nil, fmt.Errorf("rollout plan for %q: %w", fleetrollout.NormalizeChannel(channel), shared.ErrNotFound)
	}
	// Copy the slice as well as the struct: a caller that mutated CanaryGroups would silently change
	// which agents are offered an update.
	plan.CanaryGroups = append([]string(nil), plan.CanaryGroups...)
	return &plan, nil
}

// Put stores the plan, replacing any existing one for the same (tenant, channel).
func (s *FleetRolloutStore) Put(_ context.Context, plan *fleetrollout.Plan) error {
	if plan == nil {
		return fmt.Errorf("%w: nil rollout plan", shared.ErrValidation)
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	stored := *plan
	stored.CanaryGroups = append([]string(nil), plan.CanaryGroups...)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.plans[rolloutKey(plan.TenantID, plan.Channel)] = stored
	return nil
}
