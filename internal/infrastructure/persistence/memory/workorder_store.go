package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// WorkOrderStore is an in-memory ports.WorkOrderStore for dev and tests. It mirrors the Postgres
// store's idempotency, in-flight uniqueness and CAS-transition semantics.
type WorkOrderStore struct {
	mu     sync.Mutex
	byID   map[string]*workorder.WorkOrder // key: tenant|id
	byIdem map[string]string               // key: tenant|idem -> id
}

// NewWorkOrderStore returns an empty in-memory work order store.
func NewWorkOrderStore() *WorkOrderStore {
	return &WorkOrderStore{byID: map[string]*workorder.WorkOrder{}, byIdem: map[string]string{}}
}

var _ ports.WorkOrderStore = (*WorkOrderStore)(nil)

func woKey(tenant, id shared.ID) string { return tenant.String() + "|" + id.String() }
func idemKey(tenant shared.ID, idem string) string {
	return tenant.String() + "|" + idem
}

// Issue stores wo. It is idempotent by (tenant, idempotency key) and rejects a second live order
// for the same (tenant, asset, capability, time bucket) with shared.ErrConflict.
func (s *WorkOrderStore) Issue(_ context.Context, wo *workorder.WorkOrder) (*workorder.WorkOrder, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existingID, ok := s.byIdem[idemKey(wo.TenantID, wo.IdempotencyKey)]; ok {
		cp := *s.byID[woKey(wo.TenantID, shared.ID(existingID))]
		return &cp, nil
	}
	for _, o := range s.byID {
		if o.TenantID == wo.TenantID && o.AssetID == wo.AssetID && o.Capability == wo.Capability &&
			o.TimeBucket == wo.TimeBucket && isLive(o.State) {
			return nil, shared.ErrConflict
		}
	}
	cp := *wo
	s.byID[woKey(wo.TenantID, wo.ID)] = &cp
	s.byIdem[idemKey(wo.TenantID, wo.IdempotencyKey)] = wo.ID.String()
	out := *wo
	return &out, nil
}

// GetByID returns the order or shared.ErrNotFound.
func (s *WorkOrderStore) GetByID(_ context.Context, tenantID, id shared.ID) (*workorder.WorkOrder, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.byID[woKey(tenantID, id)]
	if !ok {
		return nil, shared.ErrNotFound
	}
	cp := *o
	return &cp, nil
}

// Claim atomically moves up to max unexpired issued orders addressed to agentID into claimed.
func (s *WorkOrderStore) Claim(_ context.Context, tenantID, agentID shared.ID, max int, now time.Time) ([]*workorder.WorkOrder, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var eligible []*workorder.WorkOrder
	for _, o := range s.byID {
		if o.TenantID == tenantID && o.AgentID == agentID && o.State == workorder.StateIssued && o.NotAfter.After(now) {
			eligible = append(eligible, o)
		}
	}
	sort.Slice(eligible, func(i, j int) bool {
		if !eligible[i].Audit.CreatedAt.Equal(eligible[j].Audit.CreatedAt) {
			return eligible[i].Audit.CreatedAt.Before(eligible[j].Audit.CreatedAt)
		}
		return eligible[i].ID < eligible[j].ID
	})
	var out []*workorder.WorkOrder
	for _, o := range eligible {
		if len(out) >= max {
			break
		}
		o.State = workorder.StateClaimed
		o.Audit.UpdatedAt = now
		cp := *o
		out = append(out, &cp)
	}
	return out, nil
}

// Transition applies to with an optimistic expected-state check (shared.ErrConflict on mismatch).
func (s *WorkOrderStore) Transition(_ context.Context, tenantID, id shared.ID, to workorder.State, reason string, expected workorder.State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.byID[woKey(tenantID, id)]
	if !ok {
		return shared.ErrNotFound
	}
	if o.State != expected {
		return shared.ErrConflict
	}
	o.State = to
	o.RefuseReason = reason
	return nil
}

func isLive(s workorder.State) bool {
	return s == workorder.StateIssued || s == workorder.StateClaimed || s == workorder.StateRunning
}
