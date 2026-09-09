package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// IncidentEventStore persists the append-only incident log and its immutable canonical-merge index.
// Every method is tenant-scoped from the context.
type IncidentEventStore interface {
	// AppendEvents appends events under optimistic concurrency. A merged event also creates its immutable
	// merge edge in the same persistence operation; callers must fold-validate the resulting log first.
	AppendEvents(ctx context.Context, incidentID shared.ID, expectedRevision int, events []incident.IncidentEvent) error
	LoadEvents(ctx context.Context, incidentID shared.ID) ([]incident.IncidentEvent, error)
	// ListIncidentIDs returns IDs in stable order. Limit 0 uses the operational default; a negative limit is
	// intentionally unbounded for canonicalization, which must deduplicate before applying a caller limit.
	ListIncidentIDs(ctx context.Context, q IncidentQuery) ([]shared.ID, error)
	// ResolveCanonicalID follows immutable merge edges to the root, rejecting malformed cyclic storage.
	ResolveCanonicalID(ctx context.Context, incidentID shared.ID) (shared.ID, error)
	// ListMergeEdges returns immutable edges whose source resolves to canonicalID, in source order.
	ListMergeEdges(ctx context.Context, canonicalID shared.ID) ([]incident.MergeEdge, error)
	ListPendingResponseLinks(ctx context.Context) ([]incident.ResponseLink, error)
}

// IncidentQuery selects incidents. An empty AssetID matches all incidents in the tenant; Limit caps the
// result (0 means the store default, negative means unbounded for internal canonicalization).
type IncidentQuery struct {
	AssetID shared.ID
	Limit   int
}
