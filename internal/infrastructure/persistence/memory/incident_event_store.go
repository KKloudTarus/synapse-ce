package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// defaultIncidentListLimit caps ListIncidentIDs; mirrors the Postgres tier.
const defaultIncidentListLimit = 1000

// IncidentEventStore is the in-memory twin of the append-only incident event log (Phase C / C7). It is
// tenant-bucketed and enforces optimistic-concurrency append by log position, upholding the same contract
// as the Postgres tier. Reached only through ports.IncidentEventStore.
type IncidentEventStore struct {
	mu   sync.Mutex
	logs map[shared.ID]map[shared.ID][]incident.IncidentEvent // tenant -> incident -> ordered events
}

var _ ports.IncidentEventStore = (*IncidentEventStore)(nil)

// NewIncidentEventStore creates an empty in-memory incident event store.
func NewIncidentEventStore() *IncidentEventStore {
	return &IncidentEventStore{logs: make(map[shared.ID]map[shared.ID][]incident.IncidentEvent)}
}

func requireIncidentTenant(ctx context.Context) (shared.ID, error) {
	if t, ok := shared.TenantFrom(ctx); ok && t != "" {
		return t, nil
	}
	return "", fmt.Errorf("%w: incident store operation requires a tenant in context", shared.ErrValidation)
}

// AppendEvents appends events under optimistic concurrency (expectedRevision must equal the current count).
func (s *IncidentEventStore) AppendEvents(ctx context.Context, incidentID shared.ID, expectedRevision int, events []incident.IncidentEvent) error {
	tenant, err := requireIncidentTenant(ctx)
	if err != nil {
		return err
	}
	if incidentID.IsZero() {
		return fmt.Errorf("%w: incident id is required", shared.ErrValidation)
	}
	if len(events) == 0 {
		return nil
	}
	for _, e := range events {
		if err := e.Validate(); err != nil {
			return err
		}
		if e.IncidentID != incidentID {
			return fmt.Errorf("%w: event belongs to %s, not %s", shared.ErrValidation, e.IncidentID, incidentID)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	byInc := s.logs[tenant]
	if byInc == nil {
		byInc = make(map[shared.ID][]incident.IncidentEvent)
		s.logs[tenant] = byInc
	}
	if len(byInc[incidentID]) != expectedRevision {
		return fmt.Errorf("%w: incident %s at revision %d, expected %d", shared.ErrConflict, incidentID, len(byInc[incidentID]), expectedRevision)
	}
	for _, e := range events {
		byInc[incidentID] = append(byInc[incidentID], cloneIncidentEvent(e))
	}
	return nil
}

// cloneIncidentEvent deep-copies the one pointer field (Risk) so the append-only in-memory log cannot be
// mutated through a pointer a caller retains; every other field is a value type. The Postgres tier is
// immune (it serializes to JSON), so this keeps the twin faithful.
func cloneIncidentEvent(e incident.IncidentEvent) incident.IncidentEvent {
	if e.Risk != nil {
		r := e.Risk.Clone()
		e.Risk = &r
	}
	return e
}

// LoadEvents returns a copy of one incident's event log in order.
func (s *IncidentEventStore) LoadEvents(ctx context.Context, incidentID shared.ID) ([]incident.IncidentEvent, error) {
	tenant, err := requireIncidentTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	log := s.logs[tenant][incidentID]
	if len(log) == 0 {
		return nil, nil
	}
	out := make([]incident.IncidentEvent, len(log))
	for i, e := range log {
		out[i] = cloneIncidentEvent(e) // deep-copy Risk so a caller cannot mutate stored history
	}
	return out, nil
}

// ListIncidentIDs returns incident ids matching the query, ordered by id.
func (s *IncidentEventStore) ListIncidentIDs(ctx context.Context, q ports.IncidentQuery) ([]shared.ID, error) {
	tenant, err := requireIncidentTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	var ids []shared.ID
	for id, log := range s.logs[tenant] {
		if len(log) == 0 {
			continue
		}
		if !q.AssetID.IsZero() && log[0].AssetID != q.AssetID {
			continue
		}
		ids = append(ids, id)
	}
	s.mu.Unlock()

	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	limit := q.Limit
	if limit <= 0 || limit > defaultIncidentListLimit {
		limit = defaultIncidentListLimit
	}
	if len(ids) > limit {
		ids = ids[:limit]
	}
	return ids, nil
}
