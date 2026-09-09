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

const defaultIncidentListLimit = 1000
const maxCanonicalHops = 1024

// IncidentEventStore is the in-memory twin of the append-only incident log and immutable merge index.
type IncidentEventStore struct {
	mu    sync.Mutex
	logs  map[shared.ID]map[shared.ID][]incident.IncidentEvent
	edges map[shared.ID]map[shared.ID]incident.MergeEdge // tenant -> source -> edge
}

var _ ports.IncidentEventStore = (*IncidentEventStore)(nil)

func NewIncidentEventStore() *IncidentEventStore {
	return &IncidentEventStore{logs: make(map[shared.ID]map[shared.ID][]incident.IncidentEvent), edges: make(map[shared.ID]map[shared.ID]incident.MergeEdge)}
}

func requireIncidentTenant(ctx context.Context) (shared.ID, error) {
	if t, ok := shared.TenantFrom(ctx); ok && t != "" {
		return t, nil
	}
	return "", fmt.Errorf("%w: incident store operation requires a tenant in context", shared.ErrValidation)
}

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
		byInc = map[shared.ID][]incident.IncidentEvent{}
		s.logs[tenant] = byInc
	}
	if len(byInc[incidentID]) != expectedRevision {
		return fmt.Errorf("%w: incident %s at revision %d, expected %d", shared.ErrConflict, incidentID, len(byInc[incidentID]), expectedRevision)
	}
	byEdge := s.edges[tenant]
	if byEdge == nil {
		byEdge = map[shared.ID]incident.MergeEdge{}
		s.edges[tenant] = byEdge
	}
	pending := make([]incident.MergeEdge, 0)
	for i, e := range events {
		if e.Kind != incident.EventMerged {
			continue
		}
		if old, ok := byEdge[incidentID]; ok {
			if old.CanonicalID == e.MergedInto && old.BridgeKey == e.CorrelationKey {
				continue
			}
			return fmt.Errorf("%w: incident %s already has immutable canonical target %s", shared.ErrConflict, incidentID, old.CanonicalID)
		}
		if len(byInc[e.MergedInto]) == 0 {
			return fmt.Errorf("%w: canonical merge target %s does not exist", shared.ErrNotFound, e.MergedInto)
		}
		root, err := resolveMemory(byEdge, e.MergedInto)
		if err != nil {
			return err
		}
		if root != e.MergedInto {
			return fmt.Errorf("%w: merge target %s is not canonical", shared.ErrConflict, e.MergedInto)
		}
		if root == incidentID {
			return fmt.Errorf("%w: incident merge would form a cycle", shared.ErrConflict)
		}
		pending = append(pending, incident.MergeEdge{SourceID: incidentID, CanonicalID: root, BridgeKey: e.CorrelationKey, SourceEventSeq: expectedRevision + i + 1, Actor: e.Actor, At: e.At})
	}
	for _, e := range events {
		byInc[incidentID] = append(byInc[incidentID], cloneIncidentEvent(e))
	}
	for _, edge := range pending {
		byEdge[edge.SourceID] = edge
	}
	return nil
}

func cloneIncidentEvent(e incident.IncidentEvent) incident.IncidentEvent {
	if e.Risk != nil {
		r := e.Risk.Clone()
		e.Risk = &r
	}
	return e
}

func (s *IncidentEventStore) LoadEvents(ctx context.Context, incidentID shared.ID) ([]incident.IncidentEvent, error) {
	tenant, err := requireIncidentTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	log := s.logs[tenant][incidentID]
	out := make([]incident.IncidentEvent, len(log))
	for i, e := range log {
		out[i] = cloneIncidentEvent(e)
	}
	return out, nil
}

func (s *IncidentEventStore) ListIncidentIDs(ctx context.Context, q ports.IncidentQuery) ([]shared.ID, error) {
	tenant, err := requireIncidentTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	var ids []shared.ID
	for id, log := range s.logs[tenant] {
		if len(log) > 0 && (q.AssetID.IsZero() || log[0].AssetID == q.AssetID) {
			ids = append(ids, id)
		}
	}
	s.mu.Unlock()
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if q.Limit == 0 {
		q.Limit = defaultIncidentListLimit
	}
	if q.Limit > 0 && len(ids) > q.Limit {
		ids = ids[:q.Limit]
	}
	return ids, nil
}

func (s *IncidentEventStore) ResolveCanonicalID(ctx context.Context, id shared.ID) (shared.ID, error) {
	tenant, err := requireIncidentTenant(ctx)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return resolveMemory(s.edges[tenant], id)
}
func resolveMemory(edges map[shared.ID]incident.MergeEdge, id shared.ID) (shared.ID, error) {
	seen := map[shared.ID]struct{}{}
	for hop := 0; hop < maxCanonicalHops; hop++ {
		if _, ok := seen[id]; ok {
			return "", fmt.Errorf("%w: incident merge cycle", shared.ErrConflict)
		}
		seen[id] = struct{}{}
		edge, ok := edges[id]
		if !ok {
			return id, nil
		}
		id = edge.CanonicalID
	}
	return "", fmt.Errorf("%w: incident merge resolution exceeds bound", shared.ErrConflict)
}
func (s *IncidentEventStore) ListMergeEdges(ctx context.Context, canonicalID shared.ID) ([]incident.MergeEdge, error) {
	tenant, err := requireIncidentTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []incident.MergeEdge
	for _, edge := range s.edges[tenant] {
		root, err := resolveMemory(s.edges[tenant], edge.SourceID)
		if err != nil {
			return nil, err
		}
		if root == canonicalID {
			out = append(out, edge)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SourceID < out[j].SourceID })
	return out, nil
}

func (s *IncidentEventStore) ListPendingResponseLinks(ctx context.Context) ([]incident.ResponseLink, error) {
	tenant, err := requireIncidentTenant(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	logs := make(map[shared.ID][]incident.IncidentEvent, len(s.logs[tenant]))
	for id, events := range s.logs[tenant] {
		logs[id] = append([]incident.IncidentEvent(nil), events...)
	}
	edges := s.edges[tenant]
	s.mu.Unlock()
	linksByKey := map[string]incident.ResponseLink{}
	for id, events := range logs {
		projection, err := incident.Project(events)
		if err != nil {
			return nil, fmt.Errorf("project incident %s response links: %w", id, err)
		}
		root, err := resolveMemory(edges, id)
		if err != nil {
			return nil, err
		}
		for _, response := range projection.Responses {
			if !response.Verified {
				linksByKey[root.String()+"\x00"+response.ActionID.String()] = incident.ResponseLink{IncidentID: root, Response: response}
			}
		}
	}
	links := make([]incident.ResponseLink, 0, len(linksByKey))
	for _, link := range linksByKey {
		links = append(links, link)
	}
	sort.Slice(links, func(i, j int) bool {
		if links[i].IncidentID != links[j].IncidentID {
			return links[i].IncidentID < links[j].IncidentID
		}
		return links[i].Response.ActionID < links[j].Response.ActionID
	})
	return links, nil
}
