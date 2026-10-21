package memory

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// DocumentStore is an in-memory conformance adapter. PostgreSQL is the durable production store.
// Every map is tenant partitioned and every returned composite value is cloned.
type DocumentStore struct {
	mu            sync.RWMutex
	engagements   *EngagementRepository
	projects      *ProjectRepository
	links         map[shared.ID]map[shared.ID]docpublish.Link
	intents       map[shared.ID]map[shared.ID]docpublish.Intent
	commands      map[shared.ID]map[shared.ID]ports.DocumentCommand
	commandChecks map[shared.ID]map[shared.ID]memoryDocumentCommandCheck
	schedules     map[shared.ID]map[shared.ID]docpublish.Schedule
	occurrences   map[shared.ID]map[shared.ID]ports.DocumentScheduleOccurrence
	deliveries    map[shared.ID]map[shared.ID]ports.DocumentScheduleDelivery
}

var _ ports.DocumentStore = (*DocumentStore)(nil)

func NewDocumentStore(engagements *EngagementRepository, projects *ProjectRepository) (*DocumentStore, error) {
	if engagements == nil || projects == nil {
		return nil, fmt.Errorf("%w: document store requires engagement and project repositories", shared.ErrValidation)
	}
	return &DocumentStore{
		engagements:   engagements,
		projects:      projects,
		links:         make(map[shared.ID]map[shared.ID]docpublish.Link),
		intents:       make(map[shared.ID]map[shared.ID]docpublish.Intent),
		commands:      make(map[shared.ID]map[shared.ID]ports.DocumentCommand),
		commandChecks: make(map[shared.ID]map[shared.ID]memoryDocumentCommandCheck),
		schedules:     make(map[shared.ID]map[shared.ID]docpublish.Schedule),
		occurrences:   make(map[shared.ID]map[shared.ID]ports.DocumentScheduleOccurrence),
		deliveries:    make(map[shared.ID]map[shared.ID]ports.DocumentScheduleDelivery),
	}, nil
}

func (s *DocumentStore) GetLink(ctx context.Context, tenant, id shared.ID) (docpublish.Link, error) {
	if err := ctx.Err(); err != nil {
		return docpublish.Link{}, err
	}
	if tenant.IsZero() || id.IsZero() {
		return docpublish.Link{}, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if link, ok := s.links[tenant][id]; ok {
		return link.Clone(), nil
	}
	return docpublish.Link{}, shared.ErrNotFound
}

func (s *DocumentStore) FindLink(ctx context.Context, tenant shared.ID, target docpublish.Target) (docpublish.Link, error) {
	if err := ctx.Err(); err != nil {
		return docpublish.Link{}, err
	}
	if tenant.IsZero() {
		return docpublish.Link{}, shared.ErrValidation
	}
	if err := target.Validate(); err != nil {
		return docpublish.Link{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if link, ok := s.linkForTarget(tenant, target); ok {
		return link.Clone(), nil
	}
	return docpublish.Link{}, shared.ErrNotFound
}

func (s *DocumentStore) linkForTarget(tenant shared.ID, target docpublish.Target) (docpublish.Link, bool) {
	for _, link := range s.links[tenant] {
		if link.Target == target {
			return link, true
		}
	}
	return docpublish.Link{}, false
}

func (s *DocumentStore) ListLinks(ctx context.Context, tenant shared.ID, scope docpublish.Scope, scopeID shared.ID, limit int) ([]docpublish.Link, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenant.IsZero() || scopeID.IsZero() || (scope != docpublish.Engagement && scope != docpublish.Project) ||
		limit < 1 || limit > docpublish.MaxListLimit {
		return nil, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]docpublish.Link, 0)
	for _, link := range s.links[tenant] {
		if link.Scope == scope && link.ScopeID == scopeID {
			out = append(out, link.Clone())
		}
	}
	// Stable order matches PostgreSQL's (created_at DESC, id DESC).
	slices.SortFunc(out, func(a, b docpublish.Link) int {
		if order := b.CreatedAt.Compare(a.CreatedAt); order != 0 {
			return order
		}
		return strings.Compare(b.ID.String(), a.ID.String())
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// validateScope mirrors the durable adapter's composite foreign keys. It reads the concrete
// parent stores directly because GetByIDInTenant hides internal project contexts, which the
// foreign key accepts, and this adapter must neither expose nor accept another tenant's rows.
func (s *DocumentStore) validateScope(ctx context.Context, tenant shared.ID, scope docpublish.Scope, scopeID shared.ID) error {
	switch scope {
	case docpublish.Engagement:
		s.engagements.mu.RLock()
		e, ok := s.engagements.data[scopeID]
		owned := ok && e.TenantID == tenant
		s.engagements.mu.RUnlock()
		if !owned {
			return shared.ErrNotFound
		}
		return nil
	case docpublish.Project:
		_, err := s.projects.GetByID(shared.WithTenant(ctx, tenant), tenant, scopeID)
		return err
	}
	return shared.ErrValidation
}

func (s *DocumentStore) CreateOrGetIntent(ctx context.Context, tenant shared.ID, intent docpublish.Intent) (docpublish.Intent, bool, error) {
	if err := ctx.Err(); err != nil {
		return docpublish.Intent{}, false, err
	}
	if err := intent.Validate(); err != nil {
		return docpublish.Intent{}, false, err
	}
	if tenant.IsZero() || intent.TenantID != tenant || intent.State != writeintent.Pending ||
		intent.Attempts != 0 || intent.Version != 1 || intent.LeaseUntil != nil {
		return docpublish.Intent{}, false, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.intents[tenant] {
		if item.IntegrationID == intent.IntegrationID && item.RequestKey == intent.RequestKey {
			if !item.SameCommand(intent) {
				return docpublish.Intent{}, false, shared.ErrConflict
			}
			return item.Clone(), false, nil
		}
		if item.ID == intent.ID || item.Marker == intent.Marker {
			return docpublish.Intent{}, false, shared.ErrConflict
		}
	}
	if err := s.validateScope(ctx, tenant, intent.Scope, intent.ScopeID); err != nil {
		return docpublish.Intent{}, false, err
	}
	switch intent.Action {
	case docpublish.Create:
		// The link exists, so its page does: a second create would make a duplicate page.
		if _, linked := s.linkForTarget(tenant, intent.Target); linked {
			return docpublish.Intent{}, false, shared.ErrConflict
		}
	case docpublish.Update:
		link, ok := s.links[tenant][intent.LinkID]
		if !ok {
			return docpublish.Intent{}, false, shared.ErrNotFound
		}
		if link.Target != intent.Target {
			return docpublish.Intent{}, false, shared.ErrValidation
		}
		if link.RetiredAt != nil {
			return docpublish.Intent{}, false, shared.ErrConflict
		}
	case docpublish.Purge:
		link, ok := s.links[tenant][intent.LinkID]
		if !ok {
			return docpublish.Intent{}, false, shared.ErrNotFound
		}
		if link.Target != intent.Target || link.RetiredAt != nil {
			return docpublish.Intent{}, false, shared.ErrConflict
		}
	}
	if s.intents[tenant] == nil {
		s.intents[tenant] = make(map[shared.ID]docpublish.Intent)
	}
	s.intents[tenant][intent.ID] = intent.Clone()
	return intent.Clone(), true, nil
}

func (s *DocumentStore) GetIntent(ctx context.Context, tenant, id shared.ID) (docpublish.Intent, error) {
	if err := ctx.Err(); err != nil {
		return docpublish.Intent{}, err
	}
	if tenant.IsZero() || id.IsZero() {
		return docpublish.Intent{}, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if item, ok := s.intents[tenant][id]; ok {
		return item.Clone(), nil
	}
	return docpublish.Intent{}, shared.ErrNotFound
}

func (s *DocumentStore) TransitionIntent(ctx context.Context, tenant, id shared.ID, expectedVersion int, change docpublish.IntentTransition, at time.Time) (docpublish.Intent, error) {
	if err := ctx.Err(); err != nil {
		return docpublish.Intent{}, err
	}
	if tenant.IsZero() || id.IsZero() || expectedVersion < 1 || at.IsZero() {
		return docpublish.Intent{}, shared.ErrValidation
	}
	// Yield is only safe with the command's clean progress checkpoint. Keep it
	// behind YieldDocumentCommand so a generic intent transition cannot clear a
	// lease while an acknowledged provider operation remains outstanding.
	if change.Event == docpublish.CheckpointYield || change.Event == docpublish.RetryDeferred {
		return docpublish.Intent{}, shared.ErrConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.intents[tenant][id]
	if !ok {
		return docpublish.Intent{}, shared.ErrNotFound
	}
	if current.Version != expectedVersion {
		return docpublish.Intent{}, shared.ErrConflict
	}
	if change.Event == writeintent.Claim {
		if command, exists := s.commands[tenant][id]; exists && !command.NextAttemptAt.IsZero() && at.Before(command.NextAttemptAt) {
			return docpublish.Intent{}, shared.ErrConflict
		}
	}
	next, err := current.Apply(change, at)
	if err != nil {
		return docpublish.Intent{}, err
	}
	var written *docpublish.Link
	if next.State == writeintent.Done {
		var existing *docpublish.Link
		if link, found := s.linkForTarget(tenant, next.Target); found {
			existing = &link
		}
		link, changed, completeErr := next.Complete(existing)
		if completeErr != nil {
			return docpublish.Intent{}, completeErr
		}
		if changed {
			written = &link
		}
	}
	if written != nil {
		written.RestrictionStatus = "unchecked"
		written.RestrictionCheckedAt = nil
		written.RestrictionNextAt = time.Time{}
		written.RestrictionCheckVersion++
		if s.links[tenant] == nil {
			s.links[tenant] = make(map[shared.ID]docpublish.Link)
		}
		s.links[tenant][written.ID] = *written
	}
	s.intents[tenant][id] = next.Clone()
	if command, ok := s.commands[tenant][id]; ok {
		command.Intent = next.Clone()
		s.commands[tenant][id] = cloneDocumentCommand(command)
	}
	return next.Clone(), nil
}
