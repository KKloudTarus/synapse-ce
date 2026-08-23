package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// IncidentEventStore persists the event-sourced incident log for Phase C (#594, C7 #681). The event log
// is the source of truth and is APPEND-ONLY (golden rule 6): an incident is reconstructed by folding its
// events with incident.Project. Every method is tenant-scoped from the context.
type IncidentEventStore interface {
	// AppendEvents appends events to one incident's log under OPTIMISTIC CONCURRENCY: expectedRevision must
	// equal the incident's current event count (0 for a brand-new incident), otherwise it returns
	// shared.ErrConflict and the caller reloads and retries. Events are assigned sequential positions after
	// expectedRevision. A duplicate concurrent append at the same position also yields ErrConflict (the log
	// position is unique), so an incident's history can never fork or lose an event. Appending zero events
	// is a no-op.
	//
	// The store validates each event and its incident binding but NOT projectability of the resulting log:
	// a caller MUST fold-validate (incident.Project over current+new) before appending, so an unprojectable
	// log — e.g. an illegal state transition — is never persisted. incidentuc.Service does this; any other
	// writer must too.
	AppendEvents(ctx context.Context, incidentID shared.ID, expectedRevision int, events []incident.IncidentEvent) error
	// LoadEvents returns one incident's full event log in log order (empty if the incident is unknown).
	LoadEvents(ctx context.Context, incidentID shared.ID) ([]incident.IncidentEvent, error)
	// ListIncidentIDs returns the incident ids matching the query, ordered by id for stability.
	ListIncidentIDs(ctx context.Context, q IncidentQuery) ([]shared.ID, error)
}

// IncidentQuery selects incidents. An empty AssetID matches all incidents in the tenant; Limit caps the
// result (0 means the store default).
type IncidentQuery struct {
	AssetID shared.ID
	Limit   int
}
