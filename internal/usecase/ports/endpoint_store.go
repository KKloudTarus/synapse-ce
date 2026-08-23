package ports

import (
	"context"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// EndpointTimelineStore persists the durable, per-asset endpoint State Timeline (Phase B / B7, #669),
// the append-only, event-time-ordered log of endpoint transitions (process/network/file/privilege) that
// Phase C correlation and retro-hunt read after the raw telemetry that produced them has expired. It is
// deliberately separate from the columnar TelemetryStore and the transport-sequencing store: it holds the
// projected transitions, not raw events or delivery bookkeeping.
//
// Every method is tenant-scoped from the context (never a caller-supplied field); the store is the durable
// home for endpoint.TimelineEntry values produced by endpoint.TimelineEntriesFor / EndpointState.Observe.
type EndpointTimelineStore interface {
	// AppendTimeline persists the given transitions idempotently: an entry whose EventID is already stored
	// for its (tenant, asset) is silently skipped, so a re-delivered or replayed envelope never duplicates
	// a transition. Every entry's TenantID must equal the context tenant, else it fails closed with
	// shared.ErrValidation (no cross-tenant write). Appending zero entries is a no-op.
	AppendTimeline(ctx context.Context, entries []endpoint.TimelineEntry) error
	// QueryTimeline returns the stored transitions matching the query, ordered by (OccurredAt, EventID
	// bytewise) — the SAME total order the in-memory timeline uses — so a persisted read reads back in the
	// same order as the in-memory projection. It is tenant-scoped from the context.
	QueryTimeline(ctx context.Context, q EndpointTimelineQuery) ([]endpoint.TimelineEntry, error)
}

// EndpointTimelineQuery selects a window of the State Timeline. AssetID is required (the timeline is
// per-asset); the rest are optional filters. A zero From/To is unbounded on that side; an empty EntityID
// or Kind does not filter on that field. Limit caps the number of rows returned (0 means the store's
// default cap); results are always ordered by (OccurredAt, EventID).
type EndpointTimelineQuery struct {
	AssetID  shared.ID
	From     time.Time
	To       time.Time
	EntityID shared.ID
	Kind     endpoint.TimelineEntryKind
	Limit    int
}
