package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type AssetInventoryRepository struct {
	mu            sync.RWMutex
	assets        map[shared.ID]asset.Asset
	versions      map[shared.ID][]asset.Version
	services      map[shared.ID]asset.BusinessService
	links         map[shared.ID][]asset.BusinessServiceAssetLink
	relationships map[shared.ID][]asset.Relationship
	owners        map[shared.ID][]asset.OwnershipAssignment
	assessments   *AssessmentRepository
}

func NewAssetInventoryRepository() *AssetInventoryRepository {
	return &AssetInventoryRepository{assets: map[shared.ID]asset.Asset{}, versions: map[shared.ID][]asset.Version{}, services: map[shared.ID]asset.BusinessService{}, links: map[shared.ID][]asset.BusinessServiceAssetLink{}, relationships: map[shared.ID][]asset.Relationship{}, owners: map[shared.ID][]asset.OwnershipAssignment{}}
}

var _ ports.AssetInventoryRepository = (*AssetInventoryRepository)(nil)

func assetTenant(ctx context.Context) (shared.ID, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok {
		return "", fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	return tenant, nil
}

func (r *AssetInventoryRepository) CreateAsset(ctx context.Context, a asset.Asset) error {
	tenant, err := assetTenant(ctx)
	if err != nil {
		return err
	}
	if a.TenantID != tenant || a.Validate() != nil {
		return fmt.Errorf("%w: invalid tenant-scoped asset", shared.ErrValidation)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.assets {
		if existing.TenantID == tenant && existing.Category == a.Category && existing.Identity == a.Identity {
			return fmt.Errorf("asset identity: %w", shared.ErrConflict)
		}
	}
	r.assets[a.ID] = a
	return nil
}

func (r *AssetInventoryRepository) GetAsset(ctx context.Context, id shared.ID) (asset.Asset, error) {
	tenant, err := assetTenant(ctx)
	if err != nil {
		return asset.Asset{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.assets[id]
	if !ok || a.TenantID != tenant {
		return asset.Asset{}, fmt.Errorf("asset %s: %w", id, shared.ErrNotFound)
	}
	return a, nil
}

func (r *AssetInventoryRepository) ListAssets(ctx context.Context) ([]asset.Asset, error) {
	tenant, err := assetTenant(ctx)
	if err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []asset.Asset{}
	for _, a := range r.assets {
		if a.TenantID == tenant {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r *AssetInventoryRepository) UpdateAsset(ctx context.Context, a asset.Asset, version asset.Version) error {
	tenant, err := assetTenant(ctx)
	if err != nil {
		return err
	}
	if a.TenantID != tenant || a.Validate() != nil || version.TenantID != tenant || version.AssetID != a.ID || version.Number != a.Version || version.Validate() != nil {
		return fmt.Errorf("%w: invalid asset update", shared.ErrValidation)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	old, ok := r.assets[a.ID]
	if !ok || old.TenantID != tenant {
		return fmt.Errorf("asset %s: %w", a.ID, shared.ErrNotFound)
	}
	if a.Version != old.Version+1 {
		return fmt.Errorf("asset %s: %w", a.ID, shared.ErrConflict)
	}
	r.assets[a.ID] = a
	r.versions[a.ID] = append(r.versions[a.ID], version)
	return nil
}

func (r *AssetInventoryRepository) ListAssetVersions(ctx context.Context, id shared.ID) ([]asset.Version, error) {
	if _, err := r.GetAsset(ctx, id); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]asset.Version(nil), r.versions[id]...), nil
}

func (r *AssetInventoryRepository) CreateBusinessService(ctx context.Context, service asset.BusinessService) error {
	tenant, err := assetTenant(ctx)
	if err != nil {
		return err
	}
	if service.TenantID != tenant || service.Validate() != nil {
		return fmt.Errorf("%w: invalid business service", shared.ErrValidation)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.services {
		if existing.TenantID == tenant && existing.Name == service.Name {
			return fmt.Errorf("business service name: %w", shared.ErrConflict)
		}
	}
	r.services[service.ID] = service
	return nil
}
func (r *AssetInventoryRepository) GetBusinessService(ctx context.Context, id shared.ID) (asset.BusinessService, error) {
	tenant, err := assetTenant(ctx)
	if err != nil {
		return asset.BusinessService{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	service, ok := r.services[id]
	if !ok || service.TenantID != tenant {
		return asset.BusinessService{}, fmt.Errorf("business service %s: %w", id, shared.ErrNotFound)
	}
	return service, nil
}
func (r *AssetInventoryRepository) ListBusinessServices(ctx context.Context) ([]asset.BusinessService, error) {
	tenant, err := assetTenant(ctx)
	if err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []asset.BusinessService{}
	for _, service := range r.services {
		if service.TenantID == tenant {
			out = append(out, service)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r *AssetInventoryRepository) UpdateBusinessService(ctx context.Context, service asset.BusinessService) error {
	tenant, err := assetTenant(ctx)
	if err != nil {
		return err
	}
	if service.TenantID != tenant || service.Validate() != nil {
		return fmt.Errorf("%w: invalid business service", shared.ErrValidation)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if current, ok := r.services[service.ID]; !ok || current.TenantID != tenant {
		return fmt.Errorf("business service %s: %w", service.ID, shared.ErrNotFound)
	}
	for id, existing := range r.services {
		if id != service.ID && existing.TenantID == tenant && existing.Name == service.Name {
			return fmt.Errorf("business service name: %w", shared.ErrConflict)
		}
	}
	r.services[service.ID] = service
	return nil
}
func (r *AssetInventoryRepository) LinkBusinessServiceAsset(ctx context.Context, link asset.BusinessServiceAssetLink) error {
	if link.Validate() != nil {
		return fmt.Errorf("%w: invalid asset link", shared.ErrValidation)
	}
	if _, err := r.GetBusinessService(ctx, link.BusinessServiceID); err != nil {
		return err
	}
	if _, err := r.GetAsset(ctx, link.AssetID); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.links[link.BusinessServiceID] {
		if existing.AssetID == link.AssetID {
			return fmt.Errorf("asset link: %w", shared.ErrConflict)
		}
	}
	r.links[link.BusinessServiceID] = append(r.links[link.BusinessServiceID], link)
	return nil
}
func (r *AssetInventoryRepository) ListBusinessServiceAssets(ctx context.Context, serviceID shared.ID) ([]asset.BusinessServiceAssetLink, error) {
	if _, err := r.GetBusinessService(ctx, serviceID); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]asset.BusinessServiceAssetLink(nil), r.links[serviceID]...), nil
}
func (r *AssetInventoryRepository) CreateRelationship(ctx context.Context, rel asset.Relationship) error {
	tenant, err := assetTenant(ctx)
	if err != nil {
		return err
	}
	if rel.TenantID != tenant || rel.Validate() != nil {
		return fmt.Errorf("%w: invalid asset relationship", shared.ErrValidation)
	}
	if _, err := r.GetAsset(ctx, rel.FromAssetID); err != nil {
		return err
	}
	if _, err := r.GetAsset(ctx, rel.ToAssetID); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.relationships[rel.FromAssetID] {
		if existing.ToAssetID == rel.ToAssetID && existing.Type == rel.Type {
			return fmt.Errorf("asset relationship: %w", shared.ErrConflict)
		}
	}
	if rel.Type == asset.RelationshipContains || rel.Type == asset.RelationshipPartOf {
		if r.reachesLocked(rel.ToAssetID, rel.FromAssetID, map[shared.ID]bool{}) {
			return fmt.Errorf("asset relationship cycle: %w", shared.ErrValidation)
		}
	}
	r.relationships[rel.FromAssetID] = append(r.relationships[rel.FromAssetID], rel)
	return nil
}
func (r *AssetInventoryRepository) reachesLocked(from, to shared.ID, seen map[shared.ID]bool) bool {
	if from == to {
		return true
	}
	if seen[from] {
		return false
	}
	seen[from] = true
	for _, rel := range r.relationships[from] {
		if rel.Type == asset.RelationshipContains || rel.Type == asset.RelationshipPartOf {
			if r.reachesLocked(rel.ToAssetID, to, seen) {
				return true
			}
		}
	}
	return false
}
func (r *AssetInventoryRepository) ListRelationships(ctx context.Context, id shared.ID) ([]asset.Relationship, error) {
	if _, err := r.GetAsset(ctx, id); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]asset.Relationship(nil), r.relationships[id]...), nil
}
func (r *AssetInventoryRepository) AssignOwner(ctx context.Context, owner asset.OwnershipAssignment) error {
	tenant, err := assetTenant(ctx)
	if err != nil {
		return err
	}
	if owner.TenantID != tenant || owner.Validate() != nil {
		return fmt.Errorf("%w: invalid ownership", shared.ErrValidation)
	}
	if _, err := r.GetAsset(ctx, owner.AssetID); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.owners[owner.AssetID] {
		if existing.Principal == owner.Principal && existing.Role == owner.Role {
			return fmt.Errorf("ownership: %w", shared.ErrConflict)
		}
	}
	r.owners[owner.AssetID] = append(r.owners[owner.AssetID], owner)
	return nil
}
func (r *AssetInventoryRepository) ListOwners(ctx context.Context, id shared.ID) ([]asset.OwnershipAssignment, error) {
	if _, err := r.GetAsset(ctx, id); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]asset.OwnershipAssignment(nil), r.owners[id]...), nil
}

func (r *AssetInventoryRepository) DeleteAsset(ctx context.Context, id shared.ID) error {
	if _, err := r.GetAsset(ctx, id); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.assets, id)
	delete(r.versions, id)
	delete(r.relationships, id)
	delete(r.owners, id)
	for from, relationships := range r.relationships {
		kept := relationships[:0]
		for _, relationship := range relationships {
			if relationship.ToAssetID != id {
				kept = append(kept, relationship)
			}
		}
		r.relationships[from] = kept
	}
	for serviceID, links := range r.links {
		kept := links[:0]
		for _, link := range links {
			if link.AssetID != id {
				kept = append(kept, link)
			}
		}
		r.links[serviceID] = kept
	}
	return nil
}

func (r *AssetInventoryRepository) DeleteBusinessService(ctx context.Context, id shared.ID) error {
	tenant, err := assetTenant(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	service, ok := r.services[id]
	if !ok || service.TenantID != tenant {
		return fmt.Errorf("business service %s: %w", id, shared.ErrNotFound)
	}
	if r.assessments != nil {
		r.assessments.mu.RLock()
		defer r.assessments.mu.RUnlock()
		for _, item := range r.assessments.items {
			if item.TenantID == tenant && item.BusinessServiceID == id {
				return fmt.Errorf("business service assessments: %w", shared.ErrConflict)
			}
		}
	}
	delete(r.services, id)
	delete(r.links, id)
	return nil
}
