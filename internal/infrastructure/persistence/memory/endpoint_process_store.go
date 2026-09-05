package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// EndpointProcessStore is the in-memory twin of the per-host process snapshot projection (B5). It is
// tenant-bucketed and upholds the same upsert-by-(tenant,asset,entity) contract as the Postgres tier.
// Reached only through ports.EndpointProcessStore.
type EndpointProcessStore struct {
	mu   sync.Mutex
	recs map[shared.ID]map[shared.ID]map[shared.ID]ports.ProcessSnapshot // tenant -> asset -> entity -> snapshot
}

var _ ports.EndpointProcessStore = (*EndpointProcessStore)(nil)

// NewEndpointProcessStore creates an empty in-memory process snapshot store.
func NewEndpointProcessStore() *EndpointProcessStore {
	return &EndpointProcessStore{recs: make(map[shared.ID]map[shared.ID]map[shared.ID]ports.ProcessSnapshot)}
}

func requireProcessTenant(ctx context.Context) (shared.ID, error) {
	if t, ok := shared.TenantFrom(ctx); ok && t != "" {
		return t, nil
	}
	return "", fmt.Errorf("%w: endpoint process store operation requires a tenant in context", shared.ErrValidation)
}

// SaveProcesses upserts snapshots by (tenant, asset, entity).
func (s *EndpointProcessStore) SaveProcesses(ctx context.Context, snapshots []ports.ProcessSnapshot) error {
	tenant, err := requireProcessTenant(ctx)
	if err != nil {
		return err
	}
	if len(snapshots) == 0 {
		return nil
	}
	for _, p := range snapshots {
		if err := p.Validate(); err != nil {
			return err
		}
		if p.TenantID != tenant {
			return fmt.Errorf("%w: snapshot tenant %q does not match context tenant %q", shared.ErrValidation, p.TenantID, tenant)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	byAsset := s.recs[tenant]
	if byAsset == nil {
		byAsset = make(map[shared.ID]map[shared.ID]ports.ProcessSnapshot)
		s.recs[tenant] = byAsset
	}
	for _, p := range snapshots {
		byEntity := byAsset[p.AssetID]
		if byEntity == nil {
			byEntity = make(map[shared.ID]ports.ProcessSnapshot)
			byAsset[p.AssetID] = byEntity
		}
		byEntity[p.EntityID] = p
	}
	return nil
}

// ReplaceRunningProcesses makes the asset's running set exactly the reported snapshots: it upserts them
// and marks every other currently-running row for that asset not-running, so a process that exited
// between reports is retired instead of lingering as running=true.
func (s *EndpointProcessStore) ReplaceRunningProcesses(ctx context.Context, assetID shared.ID, snapshots []ports.ProcessSnapshot) error {
	tenant, err := requireProcessTenant(ctx)
	if err != nil {
		return err
	}
	for _, p := range snapshots {
		if err := p.Validate(); err != nil {
			return err
		}
		if p.TenantID != tenant {
			return fmt.Errorf("%w: snapshot tenant %q does not match context tenant %q", shared.ErrValidation, p.TenantID, tenant)
		}
	}
	reported := make(map[shared.ID]struct{}, len(snapshots))
	for _, p := range snapshots {
		reported[p.EntityID] = struct{}{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	byAsset := s.recs[tenant]
	if byAsset == nil {
		byAsset = make(map[shared.ID]map[shared.ID]ports.ProcessSnapshot)
		s.recs[tenant] = byAsset
	}
	byEntity := byAsset[assetID]
	if byEntity == nil {
		byEntity = make(map[shared.ID]ports.ProcessSnapshot)
		byAsset[assetID] = byEntity
	}
	// Retire any running row absent from the report.
	for id, rec := range byEntity {
		if _, ok := reported[id]; !ok && rec.Running {
			rec.Running = false
			byEntity[id] = rec
		}
	}
	// Upsert the reported set.
	for _, p := range snapshots {
		byEntity[p.EntityID] = p
	}
	return nil
}

// ListRunningByAsset returns the running snapshots for an asset, ordered by EntityID.
func (s *EndpointProcessStore) ListRunningByAsset(ctx context.Context, assetID shared.ID) ([]ports.ProcessSnapshot, error) {
	tenant, err := requireProcessTenant(ctx)
	if err != nil {
		return nil, err
	}
	if assetID.IsZero() {
		return nil, fmt.Errorf("%w: asset id is required", shared.ErrValidation)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ports.ProcessSnapshot, 0)
	for _, p := range s.recs[tenant][assetID] {
		if p.Running {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EntityID < out[j].EntityID })
	return out, nil
}
