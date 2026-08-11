package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	pcdom "github.com/KKloudTarus/synapse-ce/internal/domain/purplecoverage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// PurpleStore is the in-memory purple-coverage store, tenant-bucketed so one tenant's coverage is never
// visible to another. Coverage is keyed (run, technique) so a re-computation of the same run replaces its
// records in place and coverage across runs forms a trend.
type PurpleStore struct {
	mu       sync.Mutex
	byTenant map[shared.ID]map[coverageKey]pcdom.Coverage
}

type coverageKey struct {
	run       shared.ID
	technique string
}

var _ ports.PurpleCoverageStore = (*PurpleStore)(nil)

// NewPurpleStore constructs the store.
func NewPurpleStore() *PurpleStore {
	return &PurpleStore{byTenant: map[shared.ID]map[coverageKey]pcdom.Coverage{}}
}

// SaveCoverage upserts a run's coverage records under the authenticated tenant. A record claiming a
// different tenant is refused so a computation cannot write into another tenant's ledger.
func (s *PurpleStore) SaveCoverage(ctx context.Context, records []pcdom.Coverage) error {
	tenant, err := requirePurpleTenant(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byTenant[tenant] == nil {
		s.byTenant[tenant] = map[coverageKey]pcdom.Coverage{}
	}
	for _, r := range records {
		if r.TenantID != "" && r.TenantID != tenant {
			return fmt.Errorf("purple coverage: record tenant %q does not match context: %w", r.TenantID, shared.ErrForbidden)
		}
		if err := r.Validate(); err != nil {
			return err
		}
		s.byTenant[tenant][coverageKey{run: r.RunID, technique: r.TechniqueID}] = r
	}
	return nil
}

// ListByRun returns one run's coverage records in the ctx tenant, ordered by technique.
func (s *PurpleStore) ListByRun(ctx context.Context, runID shared.ID) ([]pcdom.Coverage, error) {
	tenant, err := requirePurpleTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []pcdom.Coverage
	for k, c := range s.byTenant[tenant] {
		if k.run == runID {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TechniqueID < out[j].TechniqueID })
	return out, nil
}

// ListByEngagement returns all coverage for an engagement in the ctx tenant, oldest first (by
// ComputedAt, then run/technique) so a trend across runs is stable.
func (s *PurpleStore) ListByEngagement(ctx context.Context, engagementID shared.ID) ([]pcdom.Coverage, error) {
	tenant, err := requirePurpleTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []pcdom.Coverage
	for _, c := range s.byTenant[tenant] {
		if c.EngagementID == engagementID {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ComputedAt.Equal(out[j].ComputedAt) {
			return out[i].ComputedAt.Before(out[j].ComputedAt)
		}
		if out[i].RunID != out[j].RunID {
			return out[i].RunID < out[j].RunID
		}
		return out[i].TechniqueID < out[j].TechniqueID
	})
	return out, nil
}

func requirePurpleTenant(ctx context.Context) (shared.ID, error) {
	if t, ok := shared.TenantFrom(ctx); ok && t != "" {
		return t, nil
	}
	return "", fmt.Errorf("purple coverage: no tenant in context: %w", shared.ErrValidation)
}
