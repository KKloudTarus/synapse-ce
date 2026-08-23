// Package endpointstate is the usecase seam over the endpoint State Timeline (Phase B / B7, #669). It
// projects normalized telemetry envelopes into durable, queryable endpoint transitions that Phase C
// correlation and retro-hunt read. It is stateless: the timeline projection is a pure per-envelope
// function (endpoint.TimelineEntriesFor), so the service holds no per-asset aggregate and is safe to run
// N-way; durability + idempotency live in the store.
package endpointstate

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service records endpoint transitions from telemetry and answers timeline queries. It is tenant-scoped
// from the context on every call.
type Service struct {
	store ports.EndpointTimelineStore
}

// NewService constructs the service over an endpoint-timeline store.
func NewService(store ports.EndpointTimelineStore) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: endpoint state service requires a timeline store", shared.ErrValidation)
	}
	return &Service{store: store}, nil
}

// Record projects one telemetry envelope into the State Timeline and persists the resulting transition(s)
// idempotently, returning what it recorded (empty for a class with no transition, e.g. a container-only
// event). It is fail-closed: a missing tenant or a malformed envelope is rejected before any write. A
// re-delivered envelope is a no-op at the store (deduped by EventID), so Record is safe to retry.
func (s *Service) Record(ctx context.Context, env telemetry.TelemetryEnvelope) ([]endpoint.TimelineEntry, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant == "" {
		return nil, fmt.Errorf("%w: recording endpoint telemetry requires a tenant in context", shared.ErrValidation)
	}
	entries, err := endpoint.TimelineEntriesFor(tenant, env)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}
	if err := s.store.AppendTimeline(ctx, entries); err != nil {
		return nil, fmt.Errorf("persist endpoint timeline: %w", err)
	}
	return entries, nil
}

// Query returns the stored State Timeline window matching q, ordered by (OccurredAt, EventID).
func (s *Service) Query(ctx context.Context, q ports.EndpointTimelineQuery) ([]endpoint.TimelineEntry, error) {
	return s.store.QueryTimeline(ctx, q)
}
