package memory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type ComponentInventoryStore struct {
	mu          sync.RWMutex
	items       []sbom.ComponentRecord
	generations map[string]int64
	current     map[string]sbom.InventoryPublication
	published   map[string]sbom.InventoryPublication
	work        map[string]sbom.InventoryWork
}

func NewComponentInventoryStore(records ...sbom.ComponentRecord) *ComponentInventoryStore {
	store := &ComponentInventoryStore{generations: map[string]int64{}, current: map[string]sbom.InventoryPublication{}, published: map[string]sbom.InventoryPublication{}, work: map[string]sbom.InventoryWork{}}
	store.items = append(store.items, records...)
	return store
}

func inventoryScopeKey(tenantID, engagementID shared.ID, scope string) string {
	return tenantID.String() + "\x00" + engagementID.String() + "\x00" + scope
}

func (s *ComponentInventoryStore) admit(admission sbom.InventoryAdmission) (sbom.InventoryAdmission, error) {
	if admission.TenantID.IsZero() || admission.EngagementID.IsZero() || admission.Scope == "" || admission.AdmittedAt.IsZero() {
		return sbom.InventoryAdmission{}, fmt.Errorf("%w: inventory admission identity is required", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := inventoryScopeKey(admission.TenantID, admission.EngagementID, admission.Scope)
	s.generations[key]++
	admission.Generation = s.generations[key]
	return admission, nil
}

var _ ports.ComponentInventoryStore = (*ComponentInventoryStore)(nil)
var _ ports.InventoryWorkStore = (*ComponentInventoryStore)(nil)

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

func (s *ComponentInventoryStore) publishSnapshot(records []sbom.ComponentRecord, publication sbom.InventoryPublication) (sbom.InventoryPublication, error) {
	for _, record := range records {
		if err := record.Validate(); err != nil {
			return sbom.InventoryPublication{}, err
		}
	}
	if err := publication.Validate(); err != nil {
		return sbom.InventoryPublication{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := inventoryScopeKey(publication.TenantID, publication.EngagementID, publication.Scope)
	publicationKey := fmt.Sprintf("%s\x00%d", key, publication.Generation)
	if existing, ok := s.published[publicationKey]; ok {
		return existing, nil
	}
	if publication.Authoritative && publication.Completeness == sbom.InventoryComplete {
		current := s.current[key]
		if s.generations[key] == publication.Generation && publication.Generation > current.Generation {
			publication.Current = true
			s.current[key] = publication
			s.work[publicationKey] = sbom.InventoryWork{Publication: publication, State: sbom.InventoryWorkPending, NextAttemptAt: publication.PublishedAt, CreatedAt: publication.PublishedAt, UpdatedAt: publication.PublishedAt}
		} else {
			publication.Superseded = true
		}
	}
	s.items = append(s.items, records...)
	s.published[publicationKey] = publication
	return publication, nil
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
	if !query.SBOMID.IsZero() {
		latest = sbom.ComponentRecord{SBOMID: query.SBOMID, InventoryScope: query.InventoryScope, InventoryGeneration: query.InventoryGeneration}
		found = true
	}
	if !found {
		return sbom.ComponentPage{}, nil
	}
	items := make([]sbom.ComponentRecord, 0)
	for _, item := range s.items {
		if item.TenantID != tenantID || item.EngagementID != query.EngagementID || item.SBOMID != latest.SBOMID {
			continue
		}
		if !query.SBOMID.IsZero() && (item.InventoryScope != query.InventoryScope || item.InventoryGeneration != query.InventoryGeneration) {
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

func (s *ComponentInventoryStore) ListSnapshotComponents(ctx context.Context, query sbom.SnapshotQuery) (sbom.ComponentPage, error) {
	if err := ctx.Err(); err != nil {
		return sbom.ComponentPage{}, err
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return sbom.ComponentPage{}, fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	if !query.TenantID.IsZero() && shared.TenantOrDefault(query.TenantID) != tenantID {
		return sbom.ComponentPage{}, fmt.Errorf("%w: snapshot query tenant does not match context", shared.ErrValidation)
	}
	query.TenantID = tenantID
	query, err := query.Normalize()
	if err != nil {
		return sbom.ComponentPage{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]sbom.ComponentRecord, 0)
	for _, item := range s.items {
		if item.TenantID == tenantID && item.EngagementID == query.EngagementID && item.SBOMID == query.SBOMID &&
			item.InventoryScope == query.InventoryScope && item.InventoryGeneration == query.InventoryGeneration && item.ComponentID > query.AfterComponentID {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ComponentID < items[j].ComponentID })
	page := sbom.ComponentPage{}
	if len(items) > query.Limit {
		page.Items = append([]sbom.ComponentRecord(nil), items[:query.Limit]...)
		last := page.Items[len(page.Items)-1]
		page.Next = &sbom.ComponentCursor{BeforeSBOMID: query.SBOMID, BeforeComponentID: last.ComponentID}
		return page, nil
	}
	page.Items = append([]sbom.ComponentRecord(nil), items...)
	return page, nil
}

func (s *ComponentInventoryStore) ListCurrentInventoryPublications(ctx context.Context, tenantID shared.ID, cursor sbom.InventoryCursor, limit int) (sbom.InventoryPublicationPage, error) {
	contextTenant, ok := shared.TenantFrom(ctx)
	tenantID = shared.TenantOrDefault(tenantID)
	if !ok || shared.TenantOrDefault(contextTenant) != tenantID {
		return sbom.InventoryPublicationPage{}, fmt.Errorf("%w: inventory publication tenant does not match context", shared.ErrValidation)
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	s.mu.RLock()
	items := make([]sbom.InventoryPublication, 0)
	for _, item := range s.current {
		if item.TenantID != tenantID || item.EngagementID < cursor.AfterEngagementID ||
			(item.EngagementID == cursor.AfterEngagementID && item.Scope <= cursor.AfterScope) {
			continue
		}
		items = append(items, item)
	}
	s.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool {
		if items[i].EngagementID != items[j].EngagementID {
			return items[i].EngagementID < items[j].EngagementID
		}
		return items[i].Scope < items[j].Scope
	})
	page := sbom.InventoryPublicationPage{}
	if len(items) > limit {
		page.Items = append([]sbom.InventoryPublication(nil), items[:limit]...)
		last := page.Items[len(page.Items)-1]
		page.Next = &sbom.InventoryCursor{AfterEngagementID: last.EngagementID, AfterScope: last.Scope}
		return page, nil
	}
	page.Items = append([]sbom.InventoryPublication(nil), items...)
	return page, nil
}

func (s *ComponentInventoryStore) GetCurrentInventoryPublication(ctx context.Context, tenantID, engagementID shared.ID, scope string) (sbom.InventoryPublication, error) {
	contextTenant, ok := shared.TenantFrom(ctx)
	tenantID = shared.TenantOrDefault(tenantID)
	if !ok || shared.TenantOrDefault(contextTenant) != tenantID || engagementID.IsZero() || scope == "" {
		return sbom.InventoryPublication{}, fmt.Errorf("%w: inventory publication identity is invalid", shared.ErrValidation)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.current[inventoryScopeKey(tenantID, engagementID, scope)]
	if !ok {
		return sbom.InventoryPublication{}, shared.ErrNotFound
	}
	return item, nil
}

func (s *ComponentInventoryStore) ClaimInventoryWork(ctx context.Context, tenantID shared.ID, owner string, at time.Time, lease time.Duration, limit int) ([]sbom.InventoryWork, error) {
	contextTenant, ok := shared.TenantFrom(ctx)
	tenantID = shared.TenantOrDefault(tenantID)
	owner = strings.TrimSpace(owner)
	if !ok || shared.TenantOrDefault(contextTenant) != tenantID || owner == "" || at.IsZero() || lease <= 0 {
		return nil, fmt.Errorf("%w: inventory work lease identity is invalid", shared.ErrValidation)
	}
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0)
	for key, work := range s.work {
		if work.Publication.TenantID != tenantID || work.State.Terminal() {
			continue
		}
		current := s.current[inventoryScopeKey(tenantID, work.Publication.EngagementID, work.Publication.Scope)]
		if current.Generation != work.Publication.Generation || current.SBOMID != work.Publication.SBOMID {
			work.State, work.Reason, work.UpdatedAt = sbom.InventoryWorkSkipped, "superseded_inventory_generation", at.UTC()
			work.LeaseOwner, work.LeaseUntil = "", nil
			s.work[key] = work
			continue
		}
		eligible := (work.State == sbom.InventoryWorkPending || work.State == sbom.InventoryWorkRetry) && !work.NextAttemptAt.After(at)
		eligible = eligible || work.State == sbom.InventoryWorkRunning && work.LeaseUntil != nil && !work.LeaseUntil.After(at)
		if eligible {
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		left, right := s.work[keys[i]], s.work[keys[j]]
		if !left.NextAttemptAt.Equal(right.NextAttemptAt) {
			return left.NextAttemptAt.Before(right.NextAttemptAt)
		}
		return keys[i] < keys[j]
	})
	if len(keys) > limit {
		keys = keys[:limit]
	}
	result := make([]sbom.InventoryWork, 0, len(keys))
	for _, key := range keys {
		work := s.work[key]
		until := at.UTC().Add(lease)
		work.State, work.Attempt, work.LeaseOwner, work.LeaseUntil, work.UpdatedAt = sbom.InventoryWorkRunning, work.Attempt+1, owner, &until, at.UTC()
		s.work[key] = work
		result = append(result, work)
	}
	return result, nil
}

func (s *ComponentInventoryStore) FinishInventoryWork(ctx context.Context, work sbom.InventoryWork, owner string, state sbom.InventoryWorkState, reason string, nextAttemptAt, at time.Time) error {
	tenantID, ok := shared.TenantFrom(ctx)
	owner = strings.TrimSpace(owner)
	if !ok || shared.TenantOrDefault(tenantID) != shared.TenantOrDefault(work.Publication.TenantID) || owner == "" || !state.Terminal() && state != sbom.InventoryWorkRetry || at.IsZero() {
		return fmt.Errorf("%w: invalid inventory work completion", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fmt.Sprintf("%s\x00%d", inventoryScopeKey(work.Publication.TenantID, work.Publication.EngagementID, work.Publication.Scope), work.Publication.Generation)
	current, exists := s.work[key]
	if !exists {
		return shared.ErrNotFound
	}
	if current.State != sbom.InventoryWorkRunning || current.LeaseOwner != owner || current.LeaseUntil == nil || !current.LeaseUntil.After(at) {
		return shared.ErrConflict
	}
	current.State, current.Reason, current.LeaseOwner, current.LeaseUntil, current.UpdatedAt = state, strings.TrimSpace(reason), "", nil, at.UTC()
	if state == sbom.InventoryWorkRetry {
		if nextAttemptAt.IsZero() || nextAttemptAt.Before(at) {
			return fmt.Errorf("%w: inventory retry time is invalid", shared.ErrValidation)
		}
		current.NextAttemptAt = nextAttemptAt.UTC()
	}
	s.work[key] = current
	return nil
}

func (s *ComponentInventoryStore) CompleteInventoryPublication(ctx context.Context, publication sbom.InventoryPublication, at time.Time) error {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok || shared.TenantOrDefault(tenantID) != shared.TenantOrDefault(publication.TenantID) || at.IsZero() {
		return fmt.Errorf("%w: invalid inventory publication completion", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fmt.Sprintf("%s\x00%d", inventoryScopeKey(publication.TenantID, publication.EngagementID, publication.Scope), publication.Generation)
	work, exists := s.work[key]
	if !exists {
		return shared.ErrNotFound
	}
	current := s.current[inventoryScopeKey(publication.TenantID, publication.EngagementID, publication.Scope)]
	if current.Generation != publication.Generation || current.SBOMID != publication.SBOMID {
		return shared.ErrConflict
	}
	work.State, work.Reason, work.LeaseOwner, work.LeaseUntil, work.UpdatedAt = sbom.InventoryWorkCompleted, "", "", nil, at.UTC()
	s.work[key] = work
	return nil
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
