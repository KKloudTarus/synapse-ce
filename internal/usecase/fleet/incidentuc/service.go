// Package incidentuc is the usecase seam over the event-sourced incident store.
package incidentuc

import (
	"context"
	"fmt"
	"sort"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type Service struct{ store ports.IncidentEventStore }

func NewService(store ports.IncidentEventStore) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: incident service requires an event store", shared.ErrValidation)
	}
	return &Service{store: store}, nil
}

// Get returns the canonical logical projection for either a root or a historical alias. Root workflow fields
// remain root-owned; immutable member evidence is unioned deterministically for the read model.
func (s *Service) Get(ctx context.Context, id shared.ID) (incident.Incident, error) {
	root, err := s.store.ResolveCanonicalID(ctx, id)
	if err != nil {
		return incident.Incident{}, err
	}
	base, err := s.physical(ctx, root)
	if err != nil {
		return incident.Incident{}, err
	}
	edges, err := s.store.ListMergeEdges(ctx, root)
	if err != nil {
		return incident.Incident{}, err
	}
	members := []incident.Member{{ID: root}}
	for _, edge := range edges {
		member, err := s.physical(ctx, edge.SourceID)
		if err != nil {
			return incident.Incident{}, err
		}
		if base.AssetID != member.AssetID || base.EngagementID != member.EngagementID {
			return incident.Incident{}, fmt.Errorf("%w: canonical incident members have conflicting asset or engagement provenance", shared.ErrConflict)
		}
		base = mergeEvidence(base, member)
		copy := edge
		members = append(members, incident.Member{ID: edge.SourceID, Edge: &copy})
	}
	sort.Slice(members, func(i, j int) bool { return members[i].ID < members[j].ID })
	base.ID = root
	base.MergedInto = ""
	base.Members = members
	return base, nil
}
func (s *Service) physical(ctx context.Context, id shared.ID) (incident.Incident, error) {
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
func mergeEvidence(root, member incident.Incident) incident.Incident {
	detections := map[shared.ID]struct{}{}
	for _, id := range root.DetectionIDs {
		detections[id] = struct{}{}
	}
	for _, id := range member.DetectionIDs {
		detections[id] = struct{}{}
	}
	root.DetectionIDs = root.DetectionIDs[:0]
	for id := range detections {
		root.DetectionIDs = append(root.DetectionIDs, id)
	}
	sort.Slice(root.DetectionIDs, func(i, j int) bool { return root.DetectionIDs[i] < root.DetectionIDs[j] })
	timelines := map[shared.ID]incident.TimelineRef{}
	for _, ref := range root.Timeline {
		timelines[ref.EventID] = ref
	}
	for _, ref := range member.Timeline {
		if _, ok := timelines[ref.EventID]; !ok {
			timelines[ref.EventID] = ref
		}
	}
	root.Timeline = root.Timeline[:0]
	for _, ref := range timelines {
		root.Timeline = append(root.Timeline, ref)
	}
	sort.Slice(root.Timeline, func(i, j int) bool {
		if !root.Timeline[i].OccurredAt.Equal(root.Timeline[j].OccurredAt) {
			return root.Timeline[i].OccurredAt.Before(root.Timeline[j].OccurredAt)
		}
		return root.Timeline[i].EventID < root.Timeline[j].EventID
	})
	if shared.SeverityRank(member.Severity) > shared.SeverityRank(root.Severity) {
		root.Severity = member.Severity
	}
	comments := append(append([]incident.Comment(nil), root.Comments...), member.Comments...)
	sort.Slice(comments, func(i, j int) bool {
		if !comments[i].At.Equal(comments[j].At) {
			return comments[i].At.Before(comments[j].At)
		}
		if comments[i].Actor != comments[j].Actor {
			return comments[i].Actor < comments[j].Actor
		}
		return comments[i].Text < comments[j].Text
	})
	root.Comments = root.Comments[:0]
	for _, comment := range comments {
		if len(root.Comments) == 0 || root.Comments[len(root.Comments)-1] != comment {
			root.Comments = append(root.Comments, comment)
		}
	}
	responses := map[shared.ID]incident.ResponseRef{}
	for _, response := range append(append([]incident.ResponseRef(nil), root.Responses...), member.Responses...) {
		current, found := responses[response.ActionID]
		if !found || (!current.Verified && response.Verified) {
			responses[response.ActionID] = response
		}
	}
	root.Responses = root.Responses[:0]
	for _, response := range responses {
		root.Responses = append(root.Responses, response)
	}
	sort.Slice(root.Responses, func(i, j int) bool { return root.Responses[i].ActionID < root.Responses[j].ActionID })
	if member.CreatedAt.Before(root.CreatedAt) {
		root.CreatedAt = member.CreatedAt
	}
	if member.UpdatedAt.After(root.UpdatedAt) {
		root.UpdatedAt = member.UpdatedAt
	}
	return root
}

// Append resolves aliases and rewrites all incoming event identities to the canonical root before validation.
func (s *Service) Append(ctx context.Context, id shared.ID, expectedRevision int, events []incident.IncidentEvent) (incident.Incident, error) {
	root, err := s.store.ResolveCanonicalID(ctx, id)
	if err != nil {
		return incident.Incident{}, err
	}
	if len(events) == 0 {
		return s.Get(ctx, root)
	}
	current, err := s.store.LoadEvents(ctx, root)
	if err != nil {
		return incident.Incident{}, err
	}
	if len(current) != expectedRevision {
		return incident.Incident{}, fmt.Errorf("%w: incident %s at revision %d, expected %d", shared.ErrConflict, root, len(current), expectedRevision)
	}
	incoming := append([]incident.IncidentEvent(nil), events...)
	for i := range incoming {
		incoming[i].IncidentID = root
	}
	combined := append(append([]incident.IncidentEvent(nil), current...), incoming...)
	if _, err := incident.Project(combined); err != nil {
		return incident.Incident{}, fmt.Errorf("append would produce an invalid incident: %w", err)
	}
	if err := s.store.AppendEvents(ctx, root, expectedRevision, incoming); err != nil {
		return incident.Incident{}, err
	}
	return s.Get(ctx, root)
}
func (s *Service) ListByAsset(ctx context.Context, asset shared.ID, limit int) ([]incident.Incident, error) {
	ids, err := s.store.ListIncidentIDs(ctx, ports.IncidentQuery{AssetID: asset, Limit: -1})
	if err != nil {
		return nil, err
	}
	seen := map[shared.ID]struct{}{}
	out := make([]incident.Incident, 0, len(ids))
	for _, id := range ids {
		root, err := s.store.ResolveCanonicalID(ctx, id)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		inc, err := s.Get(ctx, root)
		if err != nil {
			return nil, err
		}
		out = append(out, inc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (s *Service) ListPendingResponseLinks(ctx context.Context) ([]incident.ResponseLink, error) {
	return s.store.ListPendingResponseLinks(ctx)
}
func (s *Service) RecordCorrelation(ctx context.Context, events []incident.IncidentEvent) (created, updated []incident.Incident, err error) {
	byIncident, order := groupByIncident(events)
	seen := map[shared.ID]struct{}{}
	for _, id := range order {
		current, err := s.store.LoadEvents(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		if len(current) == 0 {
			inc, err := s.Append(ctx, id, 0, byIncident[id])
			if err != nil {
				return nil, nil, err
			}
			if _, ok := seen[inc.ID]; !ok {
				created = append(created, inc)
				seen[inc.ID] = struct{}{}
			}
			continue
		}
		incoming := correlationDelta(current, byIncident[id])
		if len(incoming) == 0 {
			continue
		}
		last := current[len(current)-1].At
		for i := range incoming {
			if incoming[i].At.Before(last) {
				incoming[i].At = last
			}
			last = incoming[i].At
		}
		inc, err := s.Append(ctx, id, len(current), incoming)
		if err != nil {
			return nil, nil, err
		}
		if _, ok := seen[inc.ID]; !ok {
			updated = append(updated, inc)
			seen[inc.ID] = struct{}{}
		}
	}
	return created, updated, nil
}
func correlationDelta(current, incoming []incident.IncidentEvent) []incident.IncidentEvent {
	keys := map[string]struct{}{}
	detections := map[shared.ID]struct{}{}
	for _, e := range current {
		if e.CorrelationKey != "" {
			keys[e.CorrelationKey] = struct{}{}
		}
		if (e.Kind == incident.EventCreated || e.Kind == incident.EventDetectionAttached) && !e.DetectionID.IsZero() {
			detections[e.DetectionID] = struct{}{}
		}
	}
	hasKey := false
	for _, e := range incoming {
		if e.CorrelationKey != "" {
			hasKey = true
			break
		}
	}
	if !hasKey {
		return nil
	}
	var delta []incident.IncidentEvent
	for _, e := range incoming {
		if e.Kind == incident.EventCreated {
			continue
		}
		if e.CorrelationKey != "" {
			if _, ok := keys[e.CorrelationKey]; ok {
				continue
			}
			keys[e.CorrelationKey] = struct{}{}
		}
		if e.Kind == incident.EventDetectionAttached {
			if _, ok := detections[e.DetectionID]; ok {
				continue
			}
			detections[e.DetectionID] = struct{}{}
		}
		delta = append(delta, e)
	}
	return delta
}
func groupByIncident(events []incident.IncidentEvent) (map[shared.ID][]incident.IncidentEvent, []shared.ID) {
	by := map[shared.ID][]incident.IncidentEvent{}
	var order []shared.ID
	for _, e := range events {
		if _, ok := by[e.IncidentID]; !ok {
			order = append(order, e.IncidentID)
		}
		by[e.IncidentID] = append(by[e.IncidentID], e)
	}
	return by, order
}
