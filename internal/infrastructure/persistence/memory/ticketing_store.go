package memory

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TicketStore is an in-memory conformance adapter. PostgreSQL is the durable production store.
// Every map is tenant partitioned and every returned composite value is cloned.
type TicketStore struct {
	mu       sync.RWMutex
	mappings map[shared.ID]map[shared.ID]ticketing.Mapping
	links    map[shared.ID]map[shared.ID]ticketing.Link
	intents  map[shared.ID]map[shared.ID]ticketing.Intent
}

var _ ports.TicketStore = (*TicketStore)(nil)

func NewTicketStore() *TicketStore {
	return &TicketStore{
		mappings: make(map[shared.ID]map[shared.ID]ticketing.Mapping),
		links:    make(map[shared.ID]map[shared.ID]ticketing.Link),
		intents:  make(map[shared.ID]map[shared.ID]ticketing.Intent),
	}
}
func (s *TicketStore) CreateMapping(ctx context.Context, tenant shared.ID, m ticketing.Mapping) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.Validate(); err != nil {
		return err
	}
	if tenant.IsZero() || m.TenantID != tenant {
		return shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.mappings[tenant] {
		if item.ID == m.ID ||
			(item.IntegrationID == m.IntegrationID && item.Scope == m.Scope && item.ScopeID == m.ScopeID) {
			return shared.ErrConflict
		}
	}
	if s.mappings[tenant] == nil {
		s.mappings[tenant] = make(map[shared.ID]ticketing.Mapping)
	}
	s.mappings[tenant][m.ID] = m.Clone()
	return nil
}
func (s *TicketStore) GetMapping(ctx context.Context, tenant, id shared.ID) (ticketing.Mapping, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Mapping{}, err
	}
	if tenant.IsZero() || id.IsZero() {
		return ticketing.Mapping{}, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if item, ok := s.mappings[tenant][id]; ok {
		return item.Clone(), nil
	}
	return ticketing.Mapping{}, shared.ErrNotFound
}
func (s *TicketStore) CreateLink(ctx context.Context, tenant shared.ID, link ticketing.Link) (ticketing.Link, bool, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Link{}, false, err
	}
	if err := link.Validate(); err != nil {
		return ticketing.Link{}, false, err
	}
	if tenant.IsZero() || tenant != link.TenantID {
		return ticketing.Link{}, false, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.links[tenant] {
		if item.FindingID == link.FindingID && item.ExternalURL == link.ExternalURL {
			if item.EngagementID != link.EngagementID || item.IntegrationID != link.IntegrationID || item.ExternalID != link.ExternalID {
				return ticketing.Link{}, false, shared.ErrConflict
			}
			return item, false, nil
		}
		if item.ID == link.ID {
			return ticketing.Link{}, false, shared.ErrConflict
		}
	}
	if s.links[tenant] == nil {
		s.links[tenant] = make(map[shared.ID]ticketing.Link)
	}
	s.links[tenant][link.ID] = link
	return link, true, nil
}
func (s *TicketStore) ListLinks(ctx context.Context, tenant, finding shared.ID) ([]ticketing.Link, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || finding.IsZero() {
		return nil, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ticketing.Link, 0)
	for _, link := range s.links[tenant] {
		if link.FindingID == finding {
			out = append(out, link)
		}
	}
	// Stable order matches PostgreSQL's (created_at DESC, id DESC).
	slices.SortFunc(out, func(a, b ticketing.Link) int {
		if order := b.CreatedAt.Compare(a.CreatedAt); order != 0 {
			return order
		}
		return strings.Compare(b.ID.String(), a.ID.String())
	})
	return out, nil
}
func (s *TicketStore) DeleteLink(ctx context.Context, tenant, id shared.ID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tenant.IsZero() || id.IsZero() {
		return shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.links[tenant][id]; !ok {
		return shared.ErrNotFound
	}
	delete(s.links[tenant], id)
	return nil
}
func sameCommand(a, b ticketing.Intent) bool {
	return a.IntegrationID == b.IntegrationID && a.MappingID == b.MappingID &&
		a.FindingID == b.FindingID && a.EngagementID == b.EngagementID && a.Action == b.Action && a.RequestKey == b.RequestKey &&
		a.PayloadDigest == b.PayloadDigest
}
func (s *TicketStore) CreateOrGetIntent(ctx context.Context, tenant shared.ID, intent ticketing.Intent) (ticketing.Intent, bool, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Intent{}, false, err
	}
	if err := intent.Validate(); err != nil {
		return ticketing.Intent{}, false, err
	}
	if tenant.IsZero() || intent.TenantID != tenant || intent.State != writeintent.Pending ||
		intent.Attempts != 0 || intent.Version != 1 || intent.LeaseUntil != nil {
		return ticketing.Intent{}, false, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.intents[tenant] {
		if item.IntegrationID == intent.IntegrationID && item.RequestKey == intent.RequestKey {
			if !sameCommand(item, intent) {
				return ticketing.Intent{}, false, shared.ErrConflict
			}
			return item.Clone(), false, nil
		}
		if item.ID == intent.ID || item.Marker == intent.Marker {
			return ticketing.Intent{}, false, shared.ErrConflict
		}
	}
	mapping, ok := s.mappings[tenant][intent.MappingID]
	if !ok || mapping.IntegrationID != intent.IntegrationID {
		return ticketing.Intent{}, false, shared.ErrNotFound
	}
	if mapping.Scope == ticketing.Engagement && mapping.ScopeID != intent.EngagementID {
		return ticketing.Intent{}, false, shared.ErrValidation
	}
	if s.intents[tenant] == nil {
		s.intents[tenant] = make(map[shared.ID]ticketing.Intent)
	}
	s.intents[tenant][intent.ID] = intent.Clone()
	return intent.Clone(), true, nil
}
func (s *TicketStore) GetIntent(ctx context.Context, tenant, id shared.ID) (ticketing.Intent, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Intent{}, err
	}
	if tenant.IsZero() || id.IsZero() {
		return ticketing.Intent{}, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if item, ok := s.intents[tenant][id]; ok {
		return item.Clone(), nil
	}
	return ticketing.Intent{}, shared.ErrNotFound
}
func (s *TicketStore) TransitionIntent(ctx context.Context, tenant, id shared.ID, expectedVersion int, event writeintent.Event, leaseUntil *time.Time, at time.Time) (ticketing.Intent, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Intent{}, err
	}
	if tenant.IsZero() || id.IsZero() || expectedVersion < 1 || at.IsZero() {
		return ticketing.Intent{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.intents[tenant][id]
	if !ok {
		return ticketing.Intent{}, shared.ErrNotFound
	}
	if current.Version != expectedVersion {
		return ticketing.Intent{}, shared.ErrConflict
	}
	if at.Before(current.UpdatedAt) {
		return ticketing.Intent{}, shared.ErrValidation
	}
	next, err := writeintent.Next(current.State, event)
	if err != nil {
		return ticketing.Intent{}, err
	}
	if event == writeintent.LeaseExpired &&
		(current.LeaseUntil == nil || at.Before(*current.LeaseUntil)) {
		return ticketing.Intent{}, shared.ErrConflict
	}
	if event == writeintent.Claim {
		if leaseUntil == nil || !leaseUntil.After(at) {
			return ticketing.Intent{}, shared.ErrValidation
		}
		nextLease := *leaseUntil
		current.LeaseUntil = &nextLease
		current.Attempts++
	} else if leaseUntil != nil {
		return ticketing.Intent{}, fmt.Errorf("%w: only a claim may set a lease", shared.ErrValidation)
	} else {
		current.LeaseUntil = nil
	}
	current.State = next
	current.Version++
	current.UpdatedAt = at.UTC()
	s.intents[tenant][id] = current.Clone()
	return current.Clone(), nil
}
