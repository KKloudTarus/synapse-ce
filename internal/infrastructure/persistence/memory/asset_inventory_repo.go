package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/businessservice"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.AssetInventoryRepository = (*AssetInventoryRepository)(nil)

// AssetInventoryRepository is a goroutine-safe, tenant-scoped development store.
type AssetInventoryRepository struct {
	mu           sync.RWMutex
	services     map[shared.ID]*businessservice.BusinessService
	serviceByKey map[string]shared.ID
	assets       map[shared.ID]*asset.Asset
	versions     map[shared.ID][]asset.Version
	links        map[shared.ID]map[shared.ID]asset.BusinessServiceLink
	relations    map[shared.ID][]asset.Relationship
}

func NewAssetInventoryRepository() *AssetInventoryRepository {
	return &AssetInventoryRepository{
		services: map[shared.ID]*businessservice.BusinessService{}, serviceByKey: map[string]shared.ID{}, assets: map[shared.ID]*asset.Asset{},
		versions: map[shared.ID][]asset.Version{}, links: map[shared.ID]map[shared.ID]asset.BusinessServiceLink{}, relations: map[shared.ID][]asset.Relationship{},
	}
}

func inventoryKey(tenantID shared.ID, value string) string { return tenantID.String() + "\x00" + value }
func cloneService(in *businessservice.BusinessService) *businessservice.BusinessService { cp := *in; return &cp }
func cloneAsset(in *asset.Asset) *asset.Asset { cp := *in; return &cp }

func (r *AssetInventoryRepository) CreateBusinessService(_ context.Context, service *businessservice.BusinessService) error {
	if service == nil { return fmt.Errorf("%w: business service is required", shared.ErrValidation) }
	r.mu.Lock(); defer r.mu.Unlock()
	key := inventoryKey(service.TenantID, service.Code)
	if _, ok := r.serviceByKey[key]; ok { return fmt.Errorf("%w: business service code already exists", shared.ErrConflict) }
	r.services[service.ID] = cloneService(service); r.serviceByKey[key] = service.ID
	return nil
}
func (r *AssetInventoryRepository) ListBusinessServices(_ context.Context, tenantID shared.ID) ([]*businessservice.BusinessService, error) {
	r.mu.RLock(); defer r.mu.RUnlock(); out := make([]*businessservice.BusinessService, 0)
	for _, service := range r.services { if service.TenantID == tenantID { out = append(out, cloneService(service)) } }
	sort.Slice(out, func(i,j int) bool { return out[i].Code < out[j].Code }); return out, nil
}
func (r *AssetInventoryRepository) GetBusinessService(_ context.Context, tenantID, id shared.ID) (*businessservice.BusinessService, error) {
	r.mu.RLock(); defer r.mu.RUnlock(); service, ok := r.services[id]
	if !ok || service.TenantID != tenantID { return nil, shared.ErrNotFound }; return cloneService(service), nil
}
func (r *AssetInventoryRepository) CreateAsset(_ context.Context, a *asset.Asset) error {
	if a == nil { return fmt.Errorf("%w: asset is required", shared.ErrValidation) }
	r.mu.Lock(); defer r.mu.Unlock()
	for _, existing := range r.assets { if existing.TenantID == a.TenantID && existing.Category == a.Category && existing.Identity == a.Identity { return fmt.Errorf("%w: asset identity already exists", shared.ErrConflict) } }
	r.assets[a.ID] = cloneAsset(a); return nil
}
func (r *AssetInventoryRepository) GetAsset(_ context.Context, tenantID, id shared.ID) (*asset.Asset, error) {
	r.mu.RLock(); defer r.mu.RUnlock(); a, ok := r.assets[id]
	if !ok || a.TenantID != tenantID { return nil, shared.ErrNotFound }; return cloneAsset(a), nil
}
func (r *AssetInventoryRepository) ListAssets(_ context.Context, tenantID shared.ID) ([]*asset.Asset, error) {
	r.mu.RLock(); defer r.mu.RUnlock(); out := make([]*asset.Asset, 0)
	for _, a := range r.assets { if a.TenantID == tenantID { out = append(out, cloneAsset(a)) } }
	sort.Slice(out, func(i,j int) bool { return out[i].Name < out[j].Name }); return out, nil
}
func (r *AssetInventoryRepository) CreateVersion(_ context.Context, version asset.Version) error {
	r.mu.Lock(); defer r.mu.Unlock(); if _, ok := r.assets[version.AssetID]; !ok { return shared.ErrNotFound }
	for _, existing := range r.versions[version.AssetID] { if existing.Value == version.Value && existing.Source == version.Source { return fmt.Errorf("%w: asset version already exists", shared.ErrConflict) } }
	r.versions[version.AssetID] = append(r.versions[version.AssetID], version); return nil
}
func (r *AssetInventoryRepository) ListVersions(_ context.Context, tenantID, assetID shared.ID) ([]asset.Version, error) {
	r.mu.RLock(); defer r.mu.RUnlock(); a, ok := r.assets[assetID]; if !ok || a.TenantID != tenantID { return nil, shared.ErrNotFound }
	out := append([]asset.Version(nil), r.versions[assetID]...); sort.Slice(out, func(i,j int) bool { return out[i].Audit.CreatedAt.After(out[j].Audit.CreatedAt) }); return out, nil
}
func (r *AssetInventoryRepository) LinkBusinessServiceAsset(_ context.Context, link asset.BusinessServiceLink) error {
	r.mu.Lock(); defer r.mu.Unlock(); service, sok := r.services[link.BusinessServiceID]; a, aok := r.assets[link.AssetID]
	if !sok || !aok || service.TenantID != a.TenantID { return shared.ErrNotFound }
	if r.links[link.BusinessServiceID] == nil { r.links[link.BusinessServiceID] = map[shared.ID]asset.BusinessServiceLink{} }
	if _, exists := r.links[link.BusinessServiceID][link.AssetID]; exists { return fmt.Errorf("%w: business service asset link already exists", shared.ErrConflict) }
	r.links[link.BusinessServiceID][link.AssetID] = link; return nil
}
func (r *AssetInventoryRepository) ListBusinessServiceAssets(_ context.Context, tenantID, serviceID shared.ID) ([]asset.BusinessServiceLink, error) {
	r.mu.RLock(); defer r.mu.RUnlock(); service, ok := r.services[serviceID]; if !ok || service.TenantID != tenantID { return nil, shared.ErrNotFound }
	out := make([]asset.BusinessServiceLink, 0, len(r.links[serviceID])); for _, link := range r.links[serviceID] { out = append(out, link) }; sort.Slice(out, func(i,j int) bool { return out[i].AssetID < out[j].AssetID }); return out, nil
}
func (r *AssetInventoryRepository) CreateRelationship(_ context.Context, tenantID shared.ID, rel asset.Relationship) error {
	r.mu.Lock(); defer r.mu.Unlock(); from, fok := r.assets[rel.FromAssetID]; to, tok := r.assets[rel.ToAssetID]
	if !fok || !tok || from.TenantID != tenantID || to.TenantID != tenantID { return shared.ErrNotFound }
	for _, existing := range r.relations[rel.FromAssetID] { if existing.ToAssetID == rel.ToAssetID && existing.Type == rel.Type { return fmt.Errorf("%w: asset relationship already exists", shared.ErrConflict) } }
	r.relations[rel.FromAssetID] = append(r.relations[rel.FromAssetID], rel); return nil
}
func (r *AssetInventoryRepository) ListRelationships(_ context.Context, tenantID, assetID shared.ID) ([]asset.Relationship, error) {
	r.mu.RLock(); defer r.mu.RUnlock(); a, ok := r.assets[assetID]; if !ok || a.TenantID != tenantID { return nil, shared.ErrNotFound }
	out := append([]asset.Relationship(nil), r.relations[assetID]...); for _, rels := range r.relations { for _, rel := range rels { if rel.ToAssetID == assetID { out = append(out, rel) } } }; return out, nil
}
