package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// defaultEndpointTimelineLimit caps an unbounded QueryTimeline so a single call cannot return an
// unbounded result set; mirrors the Postgres tier.
const defaultEndpointTimelineLimit = 10000

// EndpointTimelineStore is the in-memory twin of the durable endpoint State Timeline (Phase B / B7). It
// is tenant-bucketed and idempotent by (tenant, asset, EventID), upholding the same contract as the
// Postgres tier. Reached only through ports.EndpointTimelineStore.
type EndpointTimelineStore struct {
	mu sync.Mutex
	// tenant -> asset -> eventID -> entry
	entries map[shared.ID]map[shared.ID]map[shared.ID]endpoint.TimelineEntry
}

var _ ports.EndpointTimelineStore = (*EndpointTimelineStore)(nil)

// NewEndpointTimelineStore creates an empty in-memory endpoint-timeline store.
func NewEndpointTimelineStore() *EndpointTimelineStore {
	return &EndpointTimelineStore{entries: make(map[shared.ID]map[shared.ID]map[shared.ID]endpoint.TimelineEntry)}
}

func requireEndpointTenant(ctx context.Context) (shared.ID, error) {
	if t, ok := shared.TenantFrom(ctx); ok && t != "" {
		return t, nil
	}
	return "", fmt.Errorf("%w: endpoint timeline operation requires a tenant in context", shared.ErrValidation)
}

// AppendTimeline persists the transitions idempotently, skipping any whose EventID is already stored for
// its (tenant, asset). Every entry's TenantID must equal the context tenant.
func (s *EndpointTimelineStore) AppendTimeline(ctx context.Context, list []endpoint.TimelineEntry) error {
	tenant, err := requireEndpointTenant(ctx)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		return nil
	}
	for _, e := range list {
		if e.TenantID != tenant {
			return fmt.Errorf("%w: timeline entry tenant %s does not match context tenant %s", shared.ErrValidation, e.TenantID, tenant)
		}
		if e.AssetID.IsZero() || e.EventID.IsZero() {
			return fmt.Errorf("%w: timeline entry requires an asset id and event id", shared.ErrValidation)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range list {
		byAsset := s.entries[tenant]
		if byAsset == nil {
			byAsset = make(map[shared.ID]map[shared.ID]endpoint.TimelineEntry)
			s.entries[tenant] = byAsset
		}
		byEvent := byAsset[e.AssetID]
		if byEvent == nil {
			byEvent = make(map[shared.ID]endpoint.TimelineEntry)
			byAsset[e.AssetID] = byEvent
		}
		if _, exists := byEvent[e.EventID]; exists {
			continue // idempotent: already recorded
		}
		byEvent[e.EventID] = e
	}
	return nil
}

// QueryTimeline returns the stored transitions matching q, ordered by (OccurredAt, EventID).
func (s *EndpointTimelineStore) QueryTimeline(ctx context.Context, q ports.EndpointTimelineQuery) ([]endpoint.TimelineEntry, error) {
	tenant, err := requireEndpointTenant(ctx)
	if err != nil {
		return nil, err
	}
	if q.AssetID.IsZero() {
		return nil, fmt.Errorf("%w: timeline query requires an asset id", shared.ErrValidation)
	}
	s.mu.Lock()
	byEvent := s.entries[tenant][q.AssetID]
	out := make([]endpoint.TimelineEntry, 0, len(byEvent))
	for _, e := range byEvent {
		if !q.From.IsZero() && e.OccurredAt.Before(q.From) {
			continue
		}
		if !q.To.IsZero() && e.OccurredAt.After(q.To) {
			continue
		}
		if !q.EntityID.IsZero() && e.EntityID != q.EntityID {
			continue
		}
		if q.Kind != "" && e.Kind != q.Kind {
			continue
		}
		out = append(out, e)
	}
	s.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if !out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].OccurredAt.Before(out[j].OccurredAt)
		}
		return out[i].EventID < out[j].EventID
	})
	limit := q.Limit
	if limit <= 0 || limit > defaultEndpointTimelineLimit {
		limit = defaultEndpointTimelineLimit
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
