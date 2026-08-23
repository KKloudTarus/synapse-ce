// Package incidentuc is the usecase seam over the event-sourced incident store (Phase C / C7, #681). It
// persists incident event logs (append-only, optimistic-concurrency) and reconstructs incidents by folding
// them with incident.Project, so the store never holds a log that would not project. It is stateless and
// tenant-scoped from the context on every call.
package incidentuc

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Service reconstructs and appends to event-sourced incidents.
type Service struct {
	store ports.IncidentEventStore
}

// NewService constructs the service over an incident event store.
func NewService(store ports.IncidentEventStore) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: incident service requires an event store", shared.ErrValidation)
	}
	return &Service{store: store}, nil
}

// Get loads an incident's event log and folds it into its projection. It returns shared.ErrNotFound if the
// incident is unknown.
func (s *Service) Get(ctx context.Context, id shared.ID) (incident.Incident, error) {
	events, err := s.store.LoadEvents(ctx, id)
	if err != nil {
		return incident.Incident{}, err
	}
	if len(events) == 0 {
		return incident.Incident{}, fmt.Errorf("%w: incident %s", shared.ErrNotFound, id)
	}
	inc, err := incident.Project(events)
	if err != nil {
		return incident.Incident{}, fmt.Errorf("get incident %s: %w", id, err)
	}
	return inc, nil
}

// Append appends events to an incident under optimistic concurrency (expectedRevision must equal the
// incident's current revision). It validates that the resulting log still projects BEFORE persisting, so
// the store never holds an unprojectable log, and returns the new projection.
func (s *Service) Append(ctx context.Context, id shared.ID, expectedRevision int, events []incident.IncidentEvent) (incident.Incident, error) {
	if len(events) == 0 {
		return s.Get(ctx, id)
	}
	current, err := s.store.LoadEvents(ctx, id)
	if err != nil {
		return incident.Incident{}, err
	}
	if len(current) != expectedRevision {
		return incident.Incident{}, fmt.Errorf("%w: incident %s at revision %d, expected %d", shared.ErrConflict, id, len(current), expectedRevision)
	}
	combined := make([]incident.IncidentEvent, 0, len(current)+len(events))
	combined = append(combined, current...)
	combined = append(combined, events...)
	projected, err := incident.Project(combined)
	if err != nil {
		return incident.Incident{}, fmt.Errorf("append would produce an invalid incident: %w", err)
	}
	if err := s.store.AppendEvents(ctx, id, expectedRevision, events); err != nil {
		return incident.Incident{}, err
	}
	return projected, nil
}

// ListByAsset returns the projected incidents for an asset (all incidents in the tenant if assetID is
// zero), ordered by incident id.
func (s *Service) ListByAsset(ctx context.Context, assetID shared.ID, limit int) ([]incident.Incident, error) {
	ids, err := s.store.ListIncidentIDs(ctx, ports.IncidentQuery{AssetID: assetID, Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]incident.Incident, 0, len(ids))
	for _, id := range ids {
		inc, err := s.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, inc)
	}
	return out, nil
}

// RecordCorrelation persists correlator output (a flat event stream, grouped by incident) as NEW
// incidents. It is IDEMPOTENT for batch correlation: an incident id that already exists is skipped (the
// correlator mints deterministic ids, so re-running over the same window records nothing new). Attaching
// new detections to an existing incident is the streaming/incremental extension and is not done here. It
// returns the incidents it created.
func (s *Service) RecordCorrelation(ctx context.Context, events []incident.IncidentEvent) ([]incident.Incident, error) {
	byIncident, order := groupByIncident(events)
	var created []incident.Incident
	for _, id := range order {
		current, err := s.store.LoadEvents(ctx, id)
		if err != nil {
			return nil, err
		}
		if len(current) > 0 {
			continue // already recorded (batch idempotency)
		}
		inc, err := s.Append(ctx, id, 0, byIncident[id])
		if err != nil {
			return nil, err
		}
		created = append(created, inc)
	}
	return created, nil
}

func groupByIncident(events []incident.IncidentEvent) (map[shared.ID][]incident.IncidentEvent, []shared.ID) {
	byIncident := make(map[shared.ID][]incident.IncidentEvent)
	var order []shared.ID
	for _, e := range events {
		if _, ok := byIncident[e.IncidentID]; !ok {
			order = append(order, e.IncidentID)
		}
		byIncident[e.IncidentID] = append(byIncident[e.IncidentID], e)
	}
	return byIncident, order
}
