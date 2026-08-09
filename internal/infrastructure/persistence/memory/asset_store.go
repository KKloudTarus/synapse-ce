package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.AssetRepository = (*AssetStore)(nil)

// AssetStore is an in-memory ports.AssetRepository for dev and tests. It mirrors the Postgres
// store's tenant scoping and deterministic ordering so behaviour matches across backends.
type AssetStore struct {
	mu             sync.Mutex
	assets         map[string]*asset.Asset // key: tenant|kind|key
	edges          map[string]*asset.Edge  // key: tenant|from|to|kind|provenance
	businessAssets map[string]*asset.BusinessAsset
	projectLinks   map[string][]asset.ComponentMembership
	technicalLinks map[string][]asset.ComponentMembership
	engagements    ports.EngagementRepository
}

// NewAssetStore returns an empty in-memory asset repository.
func NewAssetStore() *AssetStore {
	return &AssetStore{
		assets:         map[string]*asset.Asset{},
		edges:          map[string]*asset.Edge{},
		businessAssets: map[string]*asset.BusinessAsset{},
		projectLinks:   map[string][]asset.ComponentMembership{},
		technicalLinks: map[string][]asset.ComponentMembership{},
	}
}

func (s *AssetStore) SetEngagementRepository(repo ports.EngagementRepository) { s.engagements = repo }

func assetKey(tenant shared.ID, kind asset.Kind, key string) string {
	return tenant.String() + "|" + string(kind) + "|" + key
}

func edgeKey(e *asset.Edge) string {
	return e.TenantID.String() + "|" + e.From.String() + "|" + e.To.String() + "|" + string(e.Kind) + "|" + e.Provenance.String()
}

// UpsertAsset stores a by its natural key, replacing any prior value for that key.
func (s *AssetStore) UpsertAsset(_ context.Context, a *asset.Asset) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *a
	cp.Attributes = cloneMap(a.Attributes)
	s.assets[assetKey(a.TenantID, a.Kind, a.Key)] = &cp
	return nil
}

// GetAssetByKey returns the asset for (tenantID, kind, key) or shared.ErrNotFound.
func (s *AssetStore) GetAssetByKey(_ context.Context, tenantID shared.ID, kind asset.Kind, key string) (*asset.Asset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.assets[assetKey(tenantID, kind, key)]
	if !ok {
		return nil, shared.ErrNotFound
	}
	cp := *a
	cp.Attributes = cloneMap(a.Attributes)
	return &cp, nil
}

// ListAssets returns the tenant's assets ordered by (kind, key).
func (s *AssetStore) ListAssets(_ context.Context, tenantID shared.ID) ([]*asset.Asset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*asset.Asset
	for _, a := range s.assets {
		if a.TenantID != tenantID {
			continue
		}
		cp := *a
		cp.Attributes = cloneMap(a.Attributes)
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Key < out[j].Key
	})
	return out, nil
}

// UpsertEdge stores e by its natural key.
func (s *AssetStore) UpsertEdge(_ context.Context, e *asset.Edge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *e
	s.edges[edgeKey(e)] = &cp
	return nil
}

// ListEdges returns the tenant's edges ordered by (from, to, kind, provenance).
func (s *AssetStore) ListEdges(_ context.Context, tenantID shared.ID) ([]*asset.Edge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*asset.Edge
	for _, e := range s.edges {
		if e.TenantID != tenantID {
			continue
		}
		cp := *e
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.From != b.From:
			return a.From < b.From
		case a.To != b.To:
			return a.To < b.To
		case a.Kind != b.Kind:
			return a.Kind < b.Kind
		default:
			return a.Provenance < b.Provenance
		}
	})
	return out, nil
}

func cloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func businessAssetIDKey(tenantID, id shared.ID) string { return tenantID.String() + "|" + id.String() }

func (s *AssetStore) CreateBusinessAsset(_ context.Context, a *asset.BusinessAsset) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.businessAssets {
		if existing.TenantID == a.TenantID && existing.Key == a.Key {
			return shared.ErrConflict
		}
	}
	cp := *a
	cp.Metadata = cloneMap(a.Metadata)
	s.businessAssets[businessAssetIDKey(a.TenantID, a.ID)] = &cp
	return nil
}
func (s *AssetStore) UpdateBusinessAsset(_ context.Context, a *asset.BusinessAsset, expectedVersion int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := businessAssetIDKey(a.TenantID, a.ID)
	current, ok := s.businessAssets[key]
	if !ok {
		return shared.ErrNotFound
	}
	if current.Version != expectedVersion {
		return shared.ErrConflict
	}
	cp := *a
	cp.Metadata = cloneMap(a.Metadata)
	s.businessAssets[key] = &cp
	return nil
}
func (s *AssetStore) GetBusinessAssetByID(_ context.Context, tenantID, id shared.ID) (*asset.BusinessAsset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.businessAssets[businessAssetIDKey(tenantID, id)]
	if !ok {
		return nil, shared.ErrNotFound
	}
	cp := *a
	cp.Metadata = cloneMap(a.Metadata)
	return &cp, nil
}
func (s *AssetStore) GetBusinessAssetByKey(_ context.Context, tenantID shared.ID, key string) (*asset.BusinessAsset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.businessAssets {
		if a.TenantID == tenantID && a.Key == key {
			cp := *a
			cp.Metadata = cloneMap(a.Metadata)
			return &cp, nil
		}
	}
	return nil, shared.ErrNotFound
}
func (s *AssetStore) ListBusinessAssets(_ context.Context, tenantID shared.ID) ([]*asset.BusinessAsset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []*asset.BusinessAsset{}
	for _, a := range s.businessAssets {
		if a.TenantID == tenantID {
			cp := *a
			cp.Metadata = cloneMap(a.Metadata)
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}
func copyLinks(in []asset.ComponentMembership) []asset.ComponentMembership {
	return append([]asset.ComponentMembership(nil), in...)
}
func (s *AssetStore) ReplaceBusinessAssetProjects(_ context.Context, tenantID, assetID shared.ID, links []asset.ComponentMembership) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.projectLinks[businessAssetIDKey(tenantID, assetID)] = copyLinks(links)
	return nil
}
func (s *AssetStore) ListBusinessAssetProjects(_ context.Context, tenantID, assetID shared.ID) ([]asset.ComponentMembership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copyLinks(s.projectLinks[businessAssetIDKey(tenantID, assetID)]), nil
}
func (s *AssetStore) ReplaceBusinessAssetTechnicalAssets(_ context.Context, tenantID, assetID shared.ID, links []asset.ComponentMembership) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.technicalLinks[businessAssetIDKey(tenantID, assetID)] = copyLinks(links)
	return nil
}
func (s *AssetStore) ListBusinessAssetTechnicalAssets(_ context.Context, tenantID, assetID shared.ID) ([]asset.ComponentMembership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return copyLinks(s.technicalLinks[businessAssetIDKey(tenantID, assetID)]), nil
}
func (s *AssetStore) AssignEngagementBusinessAsset(ctx context.Context, tenantID, engagementID, assetID shared.ID) error {
	if s.engagements == nil {
		return shared.ErrNotFound
	}
	e, err := s.engagements.GetByIDInTenant(ctx, tenantID, engagementID)
	if err != nil {
		return err
	}
	cp := *e
	cp.BusinessAssetID = assetID
	return s.engagements.Update(ctx, &cp)
}
func (s *AssetStore) ListEngagementsByBusinessAsset(ctx context.Context, tenantID, assetID shared.ID) ([]*engagement.Engagement, error) {
	if s.engagements == nil {
		return []*engagement.Engagement{}, nil
	}
	all, err := s.engagements.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := []*engagement.Engagement{}
	for _, e := range all {
		if e.BusinessAssetID == assetID {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Audit.UpdatedAt.After(out[j].Audit.UpdatedAt) })
	return out, nil
}
