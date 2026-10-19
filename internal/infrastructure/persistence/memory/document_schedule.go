package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.DocumentScheduleStore = (*DocumentStore)(nil)

func cloneScheduleOccurrence(in ports.DocumentScheduleOccurrence) ports.DocumentScheduleOccurrence {
	out := in
	out.Artifact = cloneDocumentArtifact(in.Artifact)
	if in.Occurrence.LeaseUntil != nil {
		v := *in.Occurrence.LeaseUntil
		out.Occurrence.LeaseUntil = &v
	}
	return out
}
func cloneScheduleDelivery(in ports.DocumentScheduleDelivery) ports.DocumentScheduleDelivery {
	out := in
	if in.LeaseUntil != nil {
		v := *in.LeaseUntil
		out.LeaseUntil = &v
	}
	return out
}

func (s *DocumentStore) SaveDocumentSchedule(ctx context.Context, tenant shared.ID, schedule docpublish.Schedule, expected int) (docpublish.Schedule, error) {
	if err := ctx.Err(); err != nil {
		return docpublish.Schedule{}, err
	}
	if tenant.IsZero() || schedule.TenantID != tenant || expected < 0 || schedule.Validate() != nil {
		return docpublish.Schedule{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.schedules[tenant] == nil {
		s.schedules[tenant] = map[shared.ID]docpublish.Schedule{}
	}
	old, exists := s.schedules[tenant][schedule.ID]
	if exists {
		if expected == 0 || old.Version != expected {
			return docpublish.Schedule{}, shared.ErrConflict
		}
		if old.Source != schedule.Source || old.Destination != schedule.Destination || old.IntegrationID != schedule.IntegrationID || old.EmailChannelID != schedule.EmailChannelID {
			return docpublish.Schedule{}, shared.ErrConflict
		}
		schedule.Version = old.Version + 1
		schedule.CreatedAt = old.CreatedAt
	} else {
		if expected != 0 || schedule.Version != 1 {
			return docpublish.Schedule{}, shared.ErrConflict
		}
		if err := s.validateScope(ctx, tenant, schedule.Source.Scope, schedule.Source.ScopeID); err != nil {
			return docpublish.Schedule{}, err
		}
	}
	s.schedules[tenant][schedule.ID] = schedule
	return schedule, nil
}
func (s *DocumentStore) GetDocumentSchedule(ctx context.Context, tenant, id shared.ID) (docpublish.Schedule, error) {
	if err := ctx.Err(); err != nil {
		return docpublish.Schedule{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.schedules[tenant][id]
	if !ok {
		return docpublish.Schedule{}, shared.ErrNotFound
	}
	return v, nil
}
func (s *DocumentStore) ListDocumentSchedules(ctx context.Context, tenant shared.ID, scope docpublish.Scope, scopeID shared.ID, limit int) ([]docpublish.Schedule, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || scopeID.IsZero() || limit < 1 || limit > docpublish.MaxListLimit {
		return nil, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []docpublish.Schedule{}
	for _, v := range s.schedules[tenant] {
		if v.Source.Scope == scope && v.Source.ScopeID == scopeID {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (s *DocumentStore) DeleteDocumentSchedule(ctx context.Context, tenant, id shared.ID, expected int, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tenant.IsZero() || id.IsZero() || expected < 1 || at.IsZero() {
		return shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.schedules[tenant][id]
	if !ok {
		return shared.ErrNotFound
	}
	if v.Version != expected {
		return shared.ErrConflict
	}
	v.Enabled = false
	v.Version++
	v.UpdatedAt = at.UTC()
	s.schedules[tenant][id] = v
	return nil
}

func scheduleOccurrenceID(id shared.ID, due time.Time) shared.ID {
	h := sha256.Sum256([]byte(id.String() + "\x00" + due.UTC().Format(time.RFC3339Nano)))
	return shared.ID("schedule:" + hex.EncodeToString(h[:16]))
}
func (s *DocumentStore) ClaimDueDocumentScheduleOccurrences(ctx context.Context, tenant shared.ID, limit int, at time.Time) ([]ports.DocumentScheduleWork, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || limit < 1 || limit > 20 || at.IsZero() {
		return nil, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.occurrences[tenant] == nil {
		s.occurrences[tenant] = map[shared.ID]ports.DocumentScheduleOccurrence{}
	}
	// A failed occurrence receives a new updated_at when it is checkpointed, so it
	// shares one bounded queue with newly due work instead of permanently taking
	// every claim. Ambiguous SMTP outcomes deliberately do not enter this queue.
	type candidate struct {
		occurrence *ports.DocumentScheduleOccurrence
		schedule   *docpublish.Schedule
		readyAt    time.Time
		kind       int
		id         shared.ID
	}
	stale := make([]ports.DocumentScheduleOccurrence, 0, limit)
	insertStale := func(occurrence ports.DocumentScheduleOccurrence) {
		stale = append(stale, occurrence)
		sort.Slice(stale, func(i, j int) bool {
			if !stale[i].Occurrence.UpdatedAt.Equal(stale[j].Occurrence.UpdatedAt) {
				return stale[i].Occurrence.UpdatedAt.Before(stale[j].Occurrence.UpdatedAt)
			}
			return stale[i].Occurrence.ID < stale[j].Occurrence.ID
		})
		if len(stale) > limit {
			stale = stale[:limit]
		}
	}
	for _, occurrence := range s.occurrences[tenant] {
		schedule, ok := s.schedules[tenant][occurrence.Occurrence.ScheduleID]
		if !ok || !schedule.Enabled || schedule.Version != occurrence.Occurrence.ScheduleVersion {
			continue
		}
		if occurrence.Occurrence.State == docpublish.OccurrencePending || occurrence.Occurrence.State == docpublish.OccurrenceFailed || (occurrence.Occurrence.State == docpublish.OccurrenceInFlight && occurrence.Occurrence.LeaseUntil != nil && !occurrence.Occurrence.LeaseUntil.After(at)) {
			insertStale(occurrence)
		}
	}
	all := make([]docpublish.Schedule, 0, limit)
	insertDueSchedule := func(schedule docpublish.Schedule) {
		all = append(all, schedule)
		sort.Slice(all, func(i, j int) bool {
			if !all[i].NextDueAt.Equal(all[j].NextDueAt) {
				return all[i].NextDueAt.Before(all[j].NextDueAt)
			}
			return all[i].ID < all[j].ID
		})
		if len(all) > limit {
			all = all[:limit]
		}
	}
	for _, v := range s.schedules[tenant] {
		if v.Enabled && !v.NextDueAt.After(at) {
			insertDueSchedule(v)
		}
	}
	candidates := make([]candidate, 0, len(stale)+len(all))
	for i := range stale {
		occurrence := stale[i]
		candidates = append(candidates, candidate{occurrence: &occurrence, readyAt: occurrence.Occurrence.UpdatedAt, kind: 1, id: occurrence.Occurrence.ID})
	}
	for i := range all {
		schedule := all[i]
		candidates = append(candidates, candidate{schedule: &schedule, readyAt: schedule.NextDueAt, id: schedule.ID})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if !candidates[i].readyAt.Equal(candidates[j].readyAt) {
			return candidates[i].readyAt.Before(candidates[j].readyAt)
		}
		if candidates[i].kind != candidates[j].kind {
			return candidates[i].kind < candidates[j].kind
		}
		return candidates[i].id < candidates[j].id
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	out := make([]ports.DocumentScheduleWork, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.occurrence != nil {
			occurrence := *candidate.occurrence
			schedule := s.schedules[tenant][occurrence.Occurrence.ScheduleID]
			lease := at.UTC().Add(5 * time.Minute)
			occurrence.Occurrence.State = docpublish.OccurrenceInFlight
			occurrence.Occurrence.LeaseUntil = &lease
			occurrence.Occurrence.Version++
			occurrence.Occurrence.UpdatedAt = at.UTC()
			s.occurrences[tenant][occurrence.Occurrence.ID] = occurrence
			out = append(out, ports.DocumentScheduleWork{Schedule: schedule, Occurrence: cloneScheduleOccurrence(occurrence)})
			continue
		}
		v := *candidate.schedule
		due := v.NextDueAt.UTC()
		oid := scheduleOccurrenceID(v.ID, due)
		occurrence, ok := s.occurrences[tenant][oid]
		if !ok {
			occurrence = ports.DocumentScheduleOccurrence{Occurrence: docpublish.ScheduleOccurrence{ID: oid, TenantID: tenant, ScheduleID: v.ID, DueAt: due, ScheduleVersion: v.Version, State: docpublish.OccurrencePending, Version: 1, CreatedAt: at.UTC(), UpdatedAt: at.UTC()}}
			s.occurrences[tenant][oid] = occurrence
		}
		lease := at.UTC().Add(5 * time.Minute)
		occurrence.Occurrence.State = docpublish.OccurrenceInFlight
		occurrence.Occurrence.LeaseUntil = &lease
		occurrence.Occurrence.Version++
		occurrence.Occurrence.UpdatedAt = at.UTC()
		s.occurrences[tenant][oid] = occurrence
		next, err := v.NextDueAfter(at)
		if err != nil {
			return nil, err
		}
		v.NextDueAt = next
		check := at.UTC()
		v.CheckedAt = &check
		v.CheckVersion++
		s.schedules[tenant][v.ID] = v
		out = append(out, ports.DocumentScheduleWork{Schedule: v, Occurrence: cloneScheduleOccurrence(occurrence)})
	}
	return out, nil
}
func (s *DocumentStore) GetDocumentScheduleOccurrence(ctx context.Context, tenant, id shared.ID) (ports.DocumentScheduleOccurrence, error) {
	if err := ctx.Err(); err != nil {
		return ports.DocumentScheduleOccurrence{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.occurrences[tenant][id]
	if !ok {
		return ports.DocumentScheduleOccurrence{}, shared.ErrNotFound
	}
	return cloneScheduleOccurrence(v), nil
}
func (s *DocumentStore) SaveDocumentScheduleOccurrence(ctx context.Context, tenant shared.ID, next ports.DocumentScheduleOccurrence, expected int, at time.Time) (ports.DocumentScheduleOccurrence, error) {
	if err := ctx.Err(); err != nil {
		return ports.DocumentScheduleOccurrence{}, err
	}
	if tenant.IsZero() || next.Occurrence.TenantID != tenant || expected < 1 || at.IsZero() || next.Occurrence.Validate() != nil {
		return ports.DocumentScheduleOccurrence{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.occurrences[tenant][next.Occurrence.ID]
	if !ok {
		return ports.DocumentScheduleOccurrence{}, shared.ErrNotFound
	}
	if old.Occurrence.Version != expected {
		return ports.DocumentScheduleOccurrence{}, shared.ErrConflict
	}
	if old.Occurrence.ScheduleID != next.Occurrence.ScheduleID || old.Occurrence.DueAt != next.Occurrence.DueAt {
		return ports.DocumentScheduleOccurrence{}, shared.ErrConflict
	}
	if old.ArtifactStored {
		if next.ArtifactStored {
			a, ea := json.Marshal(old.Artifact)
			b, eb := json.Marshal(next.Artifact)
			if ea != nil || eb != nil || !bytes.Equal(a, b) || old.Occurrence.ArtifactDigest != next.Occurrence.ArtifactDigest {
				return ports.DocumentScheduleOccurrence{}, shared.ErrConflict
			}
		}
		next.Artifact, next.ArtifactStored, next.Occurrence.ArtifactDigest = old.Artifact, true, old.Occurrence.ArtifactDigest
	}
	next.Occurrence.Version = old.Occurrence.Version + 1
	next.Occurrence.UpdatedAt = at.UTC()
	s.occurrences[tenant][next.Occurrence.ID] = cloneScheduleOccurrence(next)
	return cloneScheduleOccurrence(next), nil
}
func (s *DocumentStore) GetDocumentScheduleDelivery(ctx context.Context, tenant, occurrenceID shared.ID, recipientHash string) (ports.DocumentScheduleDelivery, error) {
	if err := ctx.Err(); err != nil {
		return ports.DocumentScheduleDelivery{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, v := range s.deliveries[tenant] {
		if v.OccurrenceID == occurrenceID && v.RecipientHash == recipientHash {
			return cloneScheduleDelivery(v), nil
		}
	}
	return ports.DocumentScheduleDelivery{}, shared.ErrNotFound
}
func (s *DocumentStore) SaveDocumentScheduleDelivery(ctx context.Context, tenant shared.ID, next ports.DocumentScheduleDelivery, expected int, at time.Time) (ports.DocumentScheduleDelivery, error) {
	if err := ctx.Err(); err != nil {
		return ports.DocumentScheduleDelivery{}, err
	}
	if tenant.IsZero() || next.TenantID != tenant || next.ID.IsZero() || next.OccurrenceID.IsZero() || next.RecipientHash == "" || next.MessageID.IsZero() || expected < 0 || at.IsZero() {
		return ports.DocumentScheduleDelivery{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deliveries[tenant] == nil {
		s.deliveries[tenant] = map[shared.ID]ports.DocumentScheduleDelivery{}
	}
	old, exists := s.deliveries[tenant][next.ID]
	if exists {
		if expected == 0 || old.Version != expected {
			return ports.DocumentScheduleDelivery{}, shared.ErrConflict
		}
		next.Version = old.Version + 1
		next.CreatedAt = old.CreatedAt
	} else {
		if expected != 0 || next.Version != 1 {
			return ports.DocumentScheduleDelivery{}, shared.ErrConflict
		}
		for _, d := range s.deliveries[tenant] {
			if d.OccurrenceID == next.OccurrenceID && d.RecipientHash == next.RecipientHash {
				return ports.DocumentScheduleDelivery{}, shared.ErrConflict
			}
		}
	}
	next.UpdatedAt = at.UTC()
	s.deliveries[tenant][next.ID] = cloneScheduleDelivery(next)
	return cloneScheduleDelivery(next), nil
}
