package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/attackpath"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// AttackPathStore is the in-memory derived binding store used by dev and tests.
type AttackPathStore struct {
	mu   sync.RWMutex
	data map[shared.ID]map[shared.ID][]attackpath.Binding
}

func NewAttackPathStore() *AttackPathStore {
	return &AttackPathStore{data: map[shared.ID]map[shared.ID][]attackpath.Binding{}}
}

var _ ports.AttackPathStore = (*AttackPathStore)(nil)

func (s *AttackPathStore) ReplaceBindings(_ context.Context, tenantID, engagementID, producer shared.ID, bindings []attackpath.Binding) error {
	bindings, err := validBindings(tenantID, engagementID, producer, bindings)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data[tenantID] == nil {
		s.data[tenantID] = map[shared.ID][]attackpath.Binding{}
	}
	current := s.data[tenantID][engagementID]
	out := current[:0]
	for _, binding := range current {
		if binding.Producer != producer {
			out = append(out, binding)
		}
	}
	s.data[tenantID][engagementID] = append(out, bindings...)
	return nil
}

func validBindings(tenantID, engagementID, producer shared.ID, bindings []attackpath.Binding) ([]attackpath.Binding, error) {
	if tenantID.IsZero() || engagementID.IsZero() || producer.IsZero() {
		return nil, fmt.Errorf("%w: attack path tenant, engagement, and producer are required", shared.ErrValidation)
	}
	out := append([]attackpath.Binding(nil), bindings...)
	for i := range out {
		b := &out[i]
		if b.TargetKind == "" {
			b.TargetKind = attackpath.TargetCanonical
		}
		if b.TenantID != tenantID || b.EngagementID != engagementID || b.Producer != producer || b.AssetID.IsZero() || b.FindingID.IsZero() || !b.TargetKind.Valid() || b.Provenance.IsZero() || !b.Confidence.Valid() {
			return nil, fmt.Errorf("%w: invalid attack path binding", shared.ErrValidation)
		}
	}
	return out, nil
}

func (s *AttackPathStore) ListBindings(_ context.Context, tenantID shared.ID) ([]attackpath.Binding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []attackpath.Binding
	for _, bindings := range s.data[tenantID] {
		out = append(out, bindings...)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.EngagementID != b.EngagementID {
			return a.EngagementID < b.EngagementID
		}
		if a.AssetID != b.AssetID {
			return a.AssetID < b.AssetID
		}
		if a.FindingID != b.FindingID {
			return a.FindingID < b.FindingID
		}
		if a.Producer != b.Producer {
			return a.Producer < b.Producer
		}
		return a.Provenance < b.Provenance
	})
	return out, nil
}
