package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type ComponentInventoryStore struct {
	mu    sync.RWMutex
	items []sbom.ComponentRecord
}

func NewComponentInventoryStore(records ...sbom.ComponentRecord) *ComponentInventoryStore {
	store := &ComponentInventoryStore{}
	store.items = append(store.items, records...)
	return store
}

var _ ports.ComponentInventoryStore = (*ComponentInventoryStore)(nil)

func (s *ComponentInventoryStore) Save(record sbom.ComponentRecord) error {
	if err := record.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.items {
		if s.items[i].TenantID == record.TenantID && s.items[i].ComponentID == record.ComponentID {
			s.items[i] = record
			return nil
		}
	}
	s.items = append(s.items, record)
	return nil
}

func (s *ComponentInventoryStore) saveSnapshot(records []sbom.ComponentRecord) error {
	for _, record := range records {
		if err := record.Validate(); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, records...)
	return nil
}

// ListCurrentComponentsByEngagement returns the components of the engagement's LATEST SBOM (by
// SBOMCreatedAt, then SBOMID), deduped by ComponentID and ordered by ComponentID — the same latest-SBOM
// semantics as the Postgres twin. It is the by-engagement enumeration the running-vs-installed join needs
// to resolve a vulnerable ComponentID to a package name (the keyed ListCurrentComponents query cannot,
// since it requires a package/CPE key the caller does not have).
func (s *ComponentInventoryStore) ListCurrentComponentsByEngagement(ctx context.Context, tenantID, engagementID shared.ID) ([]sbom.ComponentRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenantID.IsZero() || engagementID.IsZero() {
		return nil, fmt.Errorf("%w: tenant and engagement are required", shared.ErrValidation)
	}
	// Defense-in-depth (mirrors ListCurrentComponents): the ctx tenant must match the requested tenant.
	ctxTenant, ok := shared.TenantFrom(ctx)
	if !ok {
		return nil, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	if shared.TenantOrDefault(ctxTenant) != shared.TenantOrDefault(tenantID) {
		return nil, fmt.Errorf("%w: component query tenant does not match context", shared.ErrValidation)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Pick the latest SBOM for (tenant, engagement) — newest SBOMCreatedAt, tie-broken by the larger SBOMID.
	var latestID shared.ID
	var latestAt time.Time
	found := false
	for _, it := range s.items {
		if it.TenantID != tenantID || it.EngagementID != engagementID {
			continue
		}
		if !found || it.SBOMCreatedAt.After(latestAt) || (it.SBOMCreatedAt.Equal(latestAt) && it.SBOMID > latestID) {
			latestAt, latestID, found = it.SBOMCreatedAt, it.SBOMID, true
		}
	}
	out := make([]sbom.ComponentRecord, 0)
	if !found {
		return out, nil
	}
	byID := make(map[shared.ID]sbom.ComponentRecord)
	for _, it := range s.items {
		if it.TenantID == tenantID && it.EngagementID == engagementID && it.SBOMID == latestID {
			byID[it.ComponentID] = it
		}
	}
	for _, r := range byID {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ComponentID < out[j].ComponentID })
	return out, nil
}

func (s *ComponentInventoryStore) ListCurrentComponents(ctx context.Context, query sbom.ComponentQuery) (sbom.ComponentPage, error) {
	if err := ctx.Err(); err != nil {
		return sbom.ComponentPage{}, err
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return sbom.ComponentPage{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	if !query.TenantID.IsZero() && shared.TenantOrDefault(query.TenantID) != tenantID {
		return sbom.ComponentPage{}, fmt.Errorf("%w: component query tenant does not match context", shared.ErrValidation)
	}
	query.TenantID = tenantID
	query, err := query.Normalize()
	if err != nil {
		return sbom.ComponentPage{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	latest, found := latestSBOM(s.items, tenantID, query.EngagementID)
	if !found {
		return sbom.ComponentPage{}, nil
	}
	items := make([]sbom.ComponentRecord, 0)
	for _, item := range s.items {
		if item.TenantID != tenantID || item.EngagementID != query.EngagementID || item.SBOMID != latest.SBOMID {
			continue
		}
		packageMatch := query.Ecosystem != "" && item.IdentityStatus == sbom.IdentityResolved && item.Ecosystem == query.Ecosystem && item.Package == query.Package
		cpeMatch := query.CPEPart != "" && item.CPEStatus == sbom.IdentityResolved && item.CPEPart == query.CPEPart && item.CPEVendor == query.CPEVendor && item.CPEProduct == query.CPEProduct
		if !packageMatch && !cpeMatch {
			continue
		}
		if afterComponentCursor(item, query.Cursor) {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return componentBefore(items[i], items[j]) })
	page := sbom.ComponentPage{}
	if len(items) > query.Limit {
		page.Items = append([]sbom.ComponentRecord(nil), items[:query.Limit]...)
		last := page.Items[len(page.Items)-1]
		page.Next = &sbom.ComponentCursor{BeforeSBOMCreatedAt: last.SBOMCreatedAt, BeforeSBOMID: last.SBOMID, BeforeComponentID: last.ComponentID}
		return page, nil
	}
	page.Items = append([]sbom.ComponentRecord(nil), items...)
	return page, nil
}

func latestSBOM(items []sbom.ComponentRecord, tenantID, engagementID shared.ID) (sbom.ComponentRecord, bool) {
	var latest sbom.ComponentRecord
	found := false
	for _, item := range items {
		if item.TenantID != tenantID || item.EngagementID != engagementID {
			continue
		}
		if !found || componentNewer(item, latest) {
			latest, found = item, true
		}
	}
	return latest, found
}

func componentNewer(left, right sbom.ComponentRecord) bool {
	if !left.SBOMCreatedAt.Equal(right.SBOMCreatedAt) {
		return left.SBOMCreatedAt.After(right.SBOMCreatedAt)
	}
	return left.SBOMID > right.SBOMID
}

func componentBefore(left, right sbom.ComponentRecord) bool {
	if !left.SBOMCreatedAt.Equal(right.SBOMCreatedAt) {
		return left.SBOMCreatedAt.After(right.SBOMCreatedAt)
	}
	if left.SBOMID != right.SBOMID {
		return left.SBOMID > right.SBOMID
	}
	return left.ComponentID > right.ComponentID
}

func afterComponentCursor(item sbom.ComponentRecord, cursor sbom.ComponentCursor) bool {
	if cursor.BeforeSBOMCreatedAt.IsZero() {
		return true
	}
	if item.SBOMCreatedAt.Before(cursor.BeforeSBOMCreatedAt) {
		return true
	}
	if item.SBOMCreatedAt.After(cursor.BeforeSBOMCreatedAt) {
		return false
	}
	if item.SBOMID < cursor.BeforeSBOMID {
		return true
	}
	if item.SBOMID > cursor.BeforeSBOMID {
		return false
	}
	return item.ComponentID < cursor.BeforeComponentID
}
