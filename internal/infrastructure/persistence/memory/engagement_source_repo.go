package memory

import (
	"context"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sourcepackage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type EngagementSourceRepository struct {
	mu    sync.Mutex
	items map[sourcePackageKey]sourcepackage.Package
}

type sourcePackageKey struct{ tenantID, versionID shared.ID }

func NewEngagementSourceRepository() *EngagementSourceRepository {
	return &EngagementSourceRepository{items: map[sourcePackageKey]sourcepackage.Package{}}
}

var _ ports.EngagementSourceRepository = (*EngagementSourceRepository)(nil)

func (r *EngagementSourceRepository) checkpoint(ctx context.Context) {
	registerTenantCheckpoint(ctx, r, func(tenantID shared.ID) func() {
		restore := captureTenantEntries(r.items, func(_ sourcePackageKey, p sourcepackage.Package) bool { return p.TenantID == tenantID })
		return func() { r.mu.Lock(); defer r.mu.Unlock(); restore() }
	})
}
func (r *EngagementSourceRepository) Create(ctx context.Context, item sourcepackage.Package) (sourcepackage.Package, bool, error) {
	if err := item.ValidateVersion(); err != nil {
		return sourcepackage.Package{}, false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, old := range r.items {
		if old.TenantID == item.TenantID && (old.EngagementID == item.EngagementID || old.VersionID == item.VersionID || old.Locator == item.Locator) {
			if old == item {
				return old, false, nil
			}
			return old, false, shared.ErrConflict
		}
	}
	if !item.ReusedFromVersionID.IsZero() {
		parent, ok := r.items[sourcePackageKey{item.TenantID, item.ReusedFromVersionID}]
		if !ok || parent.TenantID != item.TenantID || parent.EngagementID == item.EngagementID || parent.ObjectKey != item.ObjectKey || parent.SHA256 != item.SHA256 || parent.Size != item.Size || parent.Filename != item.Filename || parent.CreatedBy != item.CreatedBy || !parent.CreatedAt.Equal(item.CreatedAt) {
			return sourcepackage.Package{}, false, shared.ErrValidation
		}
	}
	r.checkpoint(ctx)
	r.items[sourcePackageKey{item.TenantID, item.VersionID}] = item
	return item, true, nil
}
func (r *EngagementSourceRepository) Get(_ context.Context, tenantID, engID shared.ID) (sourcepackage.Package, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, item := range r.items {
		if item.TenantID == tenantID && item.EngagementID == engID {
			return item, nil
		}
	}
	return sourcepackage.Package{}, shared.ErrNotFound
}
func (r *EngagementSourceRepository) GetByVersion(ctx context.Context, tenantID, engID, versionID shared.ID) (sourcepackage.Package, error) {
	item, err := r.Get(ctx, tenantID, engID)
	if err == nil && item.VersionID != versionID {
		return sourcepackage.Package{}, shared.ErrNotFound
	}
	return item, err
}
func (r *EngagementSourceRepository) GetByLocator(_ context.Context, tenantID shared.ID, locator string) (sourcepackage.Package, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, item := range r.items {
		if item.TenantID == tenantID && item.Locator == locator {
			return item, nil
		}
	}
	return sourcepackage.Package{}, shared.ErrNotFound
}
func (r *EngagementSourceRepository) Delete(ctx context.Context, tenantID, engID shared.ID) (sourcepackage.Package, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var item sourcepackage.Package
	for _, candidate := range r.items {
		if candidate.TenantID == tenantID && candidate.EngagementID == engID {
			item = candidate
			break
		}
	}
	if item.VersionID.IsZero() {
		return item, false, shared.ErrNotFound
	}
	for _, candidate := range r.items {
		if candidate.TenantID == tenantID && candidate.ReusedFromVersionID == item.VersionID {
			return item, false, shared.ErrConflict
		}
	}
	r.checkpoint(ctx)
	delete(r.items, sourcePackageKey{item.TenantID, item.VersionID})
	unreferenced := true
	for _, candidate := range r.items {
		if candidate.TenantID == tenantID && candidate.ObjectKey == item.ObjectKey {
			unreferenced = false
		}
	}
	_, inTransaction := ctx.Value(tenantTransactionKey{}).(*tenantTransaction)
	return item, unreferenced && !inTransaction, nil
}

func (r *EngagementSourceRepository) ObjectUnreferenced(ctx context.Context, tenantID shared.ID, objectKey string) (bool, error) {
	if _, inTransaction := ctx.Value(tenantTransactionKey{}).(*tenantTransaction); inTransaction {
		return false, nil // Defer cleanup until the enclosing transaction finishes.
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, item := range r.items {
		if item.TenantID == tenantID && item.ObjectKey == objectKey {
			return false, nil
		}
	}
	return true, nil
}
