package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.AssetRepository = (*AssetStore)(nil)

// AssetStore is an in-memory ports.AssetRepository for dev and tests. It mirrors the Postgres
// store's tenant scoping and deterministic ordering so behaviour matches across backends.
type AssetStore struct {
	mu       sync.Mutex
	assets   map[string]*asset.Asset           // key: tenant|kind|key
	edges    map[string]*asset.Edge            // key: tenant|from|to|kind|provenance
	services map[string]*asset.BusinessService // key: tenant|name
}

// NewAssetStore returns an empty in-memory asset repository.
func NewAssetStore() *AssetStore {
	return &AssetStore{
		assets:   map[string]*asset.Asset{},
		edges:    map[string]*asset.Edge{},
		services: map[string]*asset.BusinessService{},
	}
}

func assetKey(tenant shared.ID, kind asset.Kind, key string) string {
	return tenant.String() + "|" + string(kind) + "|" + key
}

func edgeKey(e *asset.Edge) string {
	return e.TenantID.String() + "|" + e.From.String() + "|" + e.To.String() + "|" + string(e.Kind) + "|" + e.Provenance.String()
}

func serviceKey(tenant shared.ID, name string) string {
	return tenant.String() + "|" + name
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

// UpsertBusinessService stores svc by (tenant, name).
func (s *AssetStore) UpsertBusinessService(_ context.Context, svc *asset.BusinessService) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *svc
	s.services[serviceKey(svc.TenantID, svc.Name)] = &cp
	return nil
}

// GetBusinessServiceByName returns the service for (tenantID, name) or shared.ErrNotFound.
func (s *AssetStore) GetBusinessServiceByName(_ context.Context, tenantID shared.ID, name string) (*asset.BusinessService, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	svc, ok := s.services[serviceKey(tenantID, name)]
	if !ok {
		return nil, shared.ErrNotFound
	}
	cp := *svc
	return &cp, nil
}

// ListBusinessServices returns the tenant's services ordered by name.
func (s *AssetStore) ListBusinessServices(_ context.Context, tenantID shared.ID) ([]*asset.BusinessService, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*asset.BusinessService
	for _, svc := range s.services {
		if svc.TenantID != tenantID {
			continue
		}
		cp := *svc
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
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
