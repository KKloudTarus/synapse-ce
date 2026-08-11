package memory

import (
	"context"
	"sort"
	"sync"

	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ResponseStore is the in-memory response-action store, tenant-bucketed so one tenant's actions are
// never visible to another. It backs idempotency, the kill-switch halt set, and the audit trail.
type ResponseStore struct {
	mu       sync.Mutex
	byTenant map[shared.ID]map[shared.ID]rdom.Record // tenant -> action id -> record
}

var _ ports.ResponseStore = (*ResponseStore)(nil)

// NewResponseStore constructs the store.
func NewResponseStore() *ResponseStore {
	return &ResponseStore{byTenant: map[shared.ID]map[shared.ID]rdom.Record{}}
}

// Get returns the record for an id in the ctx tenant.
func (s *ResponseStore) Get(ctx context.Context, id shared.ID) (rdom.Record, bool, error) {
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return rdom.Record{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byTenant[tenant][id]
	return r, ok, nil
}

// Put upserts a record under the authenticated tenant; a record claiming a different tenant is refused.
func (s *ResponseStore) Put(ctx context.Context, r rdom.Record) error {
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return err
	}
	if r.TenantID != "" && r.TenantID != tenant {
		return shared.ErrForbidden
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byTenant[tenant] == nil {
		s.byTenant[tenant] = map[shared.ID]rdom.Record{}
	}
	s.byTenant[tenant][r.ID] = r
	return nil
}

// ListByState returns the ctx tenant's records in the given state, deterministically ordered by id.
func (s *ResponseStore) ListByState(ctx context.Context, state rdom.State) ([]rdom.Record, error) {
	tenant, err := requireResponseTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []rdom.Record
	for _, r := range s.byTenant[tenant] {
		if r.State == state {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func requireResponseTenant(ctx context.Context) (shared.ID, error) {
	if t, ok := shared.TenantFrom(ctx); ok && t != "" {
		return t, nil
	}
	return "", shared.ErrValidation
}
