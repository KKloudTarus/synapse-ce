// Package memory provides in-memory repository implementations for the walking
// skeleton and tests. Replaced by the Postgres adapters.
package memory

import (
	"context"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// EngagementRepository is a goroutine-safe in-memory engagement store.
type EngagementRepository struct {
	mu   sync.RWMutex
	data map[shared.ID]*engagement.Engagement
}

// NewEngagementRepository returns an empty in-memory repository.
func NewEngagementRepository() *EngagementRepository {
	return &EngagementRepository{data: make(map[shared.ID]*engagement.Engagement)}
}

// Compile-time assertion that we satisfy the port.
var _ ports.EngagementRepository = (*EngagementRepository)(nil)

func (r *EngagementRepository) Create(_ context.Context, e *engagement.Engagement) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data[e.ID] = e
	return nil
}

func (r *EngagementRepository) GetByID(_ context.Context, id shared.ID) (*engagement.Engagement, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.data[id]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return e, nil
}

// GetByIDInTenant loads an engagement scoped to tenantID. A caller tenant of ”
// matches any row; a non-empty tenant matches only its own – tenant A cannot read tenant B's
// engagement (ErrNotFound).
func (r *EngagementRepository) GetByIDInTenant(_ context.Context, tenantID, id shared.ID) (*engagement.Engagement, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.data[id]
	if !ok {
		return nil, shared.ErrNotFound
	}
	if !tenantID.IsZero() && e.TenantID != tenantID {
		return nil, shared.ErrNotFound // cross-tenant access – do not reveal existence
	}
	return e, nil
}

func (r *EngagementRepository) Update(_ context.Context, e *engagement.Engagement) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.data[e.ID]; !ok {
		return shared.ErrNotFound
	}
	r.data[e.ID] = e
	return nil
}

// Delete removes an engagement (idempotent). In Postgres the FK cascade removes
// children; in memory other stores are independent, but import rollback only needs
// the engagement gone so a re-import isn't blocked.
func (r *EngagementRepository) Delete(_ context.Context, id shared.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.data, id)
	return nil
}

func (r *EngagementRepository) List(_ context.Context, tenantID shared.ID) ([]*engagement.Engagement, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*engagement.Engagement, 0, len(r.data))
	for _, e := range r.data {
		if tenantID.IsZero() || e.TenantID == tenantID {
			out = append(out, e)
		}
	}
	return out, nil
}
