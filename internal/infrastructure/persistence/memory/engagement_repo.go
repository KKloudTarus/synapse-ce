// Package memory provides in-memory repository implementations for the walking
// skeleton and tests. Replaced by the Postgres adapters.
package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

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
var _ ports.PromotionReconciliationScopeReader = (*EngagementRepository)(nil)
var _ ports.VulnerabilityReconciliationTenantStore = (*EngagementRepository)(nil)
var _ ports.DetectionReconciliationTenantStore = (*EngagementRepository)(nil)
var _ ports.VulnerabilityReconciliationEngagementStore = (*EngagementRepository)(nil)

func (r *EngagementRepository) Create(_ context.Context, e *engagement.Engagement) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e.TenantID = shared.TenantOrDefault(e.TenantID)
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

// GetByIDInTenant loads an engagement scoped to tenantID. Empty input normalizes to the non-empty
// default tenant; it is never a wildcard.
func (r *EngagementRepository) GetByIDInTenant(_ context.Context, tenantID, id shared.ID) (*engagement.Engagement, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tenantID = shared.TenantOrDefault(tenantID)
	e, ok := r.data[id]
	if !ok {
		return nil, shared.ErrNotFound
	}
	if e.Internal() || e.TenantID != tenantID {
		return nil, shared.ErrNotFound // cross-tenant/internal access – do not reveal existence
	}
	return e, nil
}

func (r *EngagementRepository) GetByHostAssetID(_ context.Context, tenantID, assetID shared.ID) (*engagement.Engagement, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tenantID = shared.TenantOrDefault(tenantID)
	if assetID.IsZero() {
		return nil, shared.ErrNotFound
	}
	for _, e := range r.data {
		if e.HostAssetID == assetID && e.TenantID == tenantID {
			return e, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (r *EngagementRepository) GetByProjectID(_ context.Context, tenantID, projectID shared.ID) (*engagement.Engagement, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tenantID = shared.TenantOrDefault(tenantID)
	for _, e := range r.data {
		if e.ProjectID == projectID && e.TenantID == tenantID {
			return e, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (r *EngagementRepository) ProjectContexts(_ context.Context, tenantID shared.ID, projectIDs []shared.ID) (map[shared.ID]*engagement.Engagement, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tenantID = shared.TenantOrDefault(tenantID)
	wanted := map[shared.ID]bool{}
	for _, id := range projectIDs {
		wanted[id] = true
	}
	out := map[shared.ID]*engagement.Engagement{}
	for _, e := range r.data {
		if wanted[e.ProjectID] && e.TenantID == tenantID {
			out[e.ProjectID] = e
		}
	}
	return out, nil
}

func (r *EngagementRepository) Update(_ context.Context, e *engagement.Engagement) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.data[e.ID]; !ok {
		return shared.ErrNotFound
	}
	e.TenantID = shared.TenantOrDefault(e.TenantID)
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

// ListPromotionReconciliationScopes returns every non-project engagement for
// process-local recovery. It is only wired by the API composition root.
func (r *EngagementRepository) ListPromotionReconciliationScopes(ctx context.Context) ([]ports.PromotionReconciliationScope, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ports.PromotionReconciliationScope, 0, len(r.data))
	for _, e := range r.data {
		if e.Internal() {
			continue
		}
		out = append(out, ports.PromotionReconciliationScope{
			TenantID:     shared.TenantOrDefault(e.TenantID),
			EngagementID: e.ID,
		})
	}
	return out, nil
}

func (r *EngagementRepository) List(_ context.Context, tenantID shared.ID) ([]*engagement.Engagement, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tenantID = shared.TenantOrDefault(tenantID)
	out := make([]*engagement.Engagement, 0, len(r.data))
	for _, e := range r.data {
		if !e.Internal() && e.TenantID == tenantID {
			out = append(out, e)
		}
	}
	return out, nil
}

func (r *EngagementRepository) ListProjectEngagements(_ context.Context, tenantID shared.ID) ([]*engagement.Engagement, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tenantID = shared.TenantOrDefault(tenantID)
	out := make([]*engagement.Engagement, 0)
	for _, e := range r.data {
		if !e.ProjectID.IsZero() && e.TenantID == tenantID {
			out = append(out, e)
		}
	}
	return out, nil
}

func (r *EngagementRepository) ListTenantIDs(_ context.Context) ([]shared.ID, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := map[shared.ID]struct{}{}
	for _, item := range r.data {
		seen[shared.TenantOrDefault(item.TenantID)] = struct{}{}
	}
	out := make([]shared.ID, 0, len(seen))
	for tenantID := range seen {
		out = append(out, tenantID)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func (r *EngagementRepository) ListReconciliationEngagements(_ context.Context, tenantID, after shared.ID, snapshotAt time.Time, limit int) (ports.ReconciliationEngagementPage, error) {
	if snapshotAt.IsZero() {
		return ports.ReconciliationEngagementPage{}, fmt.Errorf("%w: reconciliation snapshot time is required", shared.ErrValidation)
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	tenantID = shared.TenantOrDefault(tenantID)
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]shared.ID, 0)
	for _, item := range r.data {
		createdAt := item.Audit.CreatedAt
		if item.TenantID == tenantID && item.ID > after && (createdAt.IsZero() || !createdAt.After(snapshotAt)) {
			ids = append(ids, item.ID)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	page := ports.ReconciliationEngagementPage{}
	if len(ids) > limit {
		page.IDs = append([]shared.ID(nil), ids[:limit]...)
		page.Next = page.IDs[len(page.IDs)-1]
		return page, nil
	}
	page.IDs = ids
	return page, nil
}
