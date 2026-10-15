package memory

import (
	"context"
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"time"
)

var _ ports.TicketAuditStore = (*TicketStore)(nil)

// The store mutex serializes validation, audit and publication. Plain foundation
// operations remain available to conformance tests; workflow mutations require audit.
func (s *TicketStore) recordTicketAuditLocked(ctx context.Context, tenant shared.ID, entry *ports.AuditEntry) error {
	if entry == nil {
		return nil
	}
	if s.audit == nil {
		return fmt.Errorf("%w: ticket audit logger required", shared.ErrValidation)
	}
	return s.audit.Record(shared.WithTenant(ctx, tenant), *entry)
}
func (s *TicketStore) CreateMapping(ctx context.Context, tenant shared.ID, m ticketing.Mapping) error {
	return s.createMapping(ctx, tenant, m, nil)
}
func (s *TicketStore) UpdateMapping(ctx context.Context, tenant shared.ID, m ticketing.Mapping, version int) (ticketing.Mapping, error) {
	return s.updateMapping(ctx, tenant, m, version, nil)
}
func (s *TicketStore) DeleteMapping(ctx context.Context, tenant, id shared.ID, version int) error {
	return s.deleteMapping(ctx, tenant, id, version, nil)
}
func (s *TicketStore) CreateMappingAudited(ctx context.Context, tenant shared.ID, m ticketing.Mapping, entry ports.AuditEntry) error {
	if err := s.validateMappingScope(ctx, tenant, m); err != nil {
		return err
	}
	return s.createMapping(ctx, tenant, m, &entry)
}
func (s *TicketStore) UpdateMappingAudited(ctx context.Context, tenant shared.ID, m ticketing.Mapping, version int, entry ports.AuditEntry) (ticketing.Mapping, error) {
	if err := s.validateMappingScope(ctx, tenant, m); err != nil {
		return ticketing.Mapping{}, err
	}
	return s.updateMapping(ctx, tenant, m, version, &entry)
}
func (s *TicketStore) DeleteMappingAudited(ctx context.Context, tenant, id shared.ID, version int, entry ports.AuditEntry) error {
	return s.deleteMapping(ctx, tenant, id, version, &entry)
}
func (s *TicketStore) CreateOrGetIntent(ctx context.Context, tenant shared.ID, i ticketing.Intent) (ticketing.Intent, bool, error) {
	return s.createOrGetIntent(ctx, tenant, i, nil)
}
func (s *TicketStore) CreateOrGetIntentAudited(ctx context.Context, tenant shared.ID, i ticketing.Intent, entry ports.AuditEntry) (ticketing.Intent, bool, error) {
	return s.createOrGetIntent(ctx, tenant, i, &entry)
}
func (s *TicketStore) TransitionIntent(ctx context.Context, tenant, id shared.ID, version int, change ticketing.IntentTransition, at time.Time) (ticketing.Intent, error) {
	return s.transitionIntent(ctx, tenant, id, version, change, at, nil)
}
func (s *TicketStore) TransitionIntentAudited(ctx context.Context, tenant, id shared.ID, version int, change ticketing.IntentTransition, at time.Time, entry ports.AuditEntry) (ticketing.Intent, error) {
	return s.transitionIntent(ctx, tenant, id, version, change, at, &entry)
}

func validTicketAudit(entry ports.AuditEntry) bool {
	return entry.Actor != "" && entry.Action != "" && entry.Target != "" && !entry.At.IsZero()
}

// RetryIntentAudited is the explicit, operator-approved duplicate-risk retry.
// The mutex keeps audit success and state publication together.
func (s *TicketStore) RetryIntentAudited(ctx context.Context, tenant, id shared.ID, expected int, at time.Time, entry ports.AuditEntry) (ticketing.Intent, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Intent{}, err
	}
	if tenant.IsZero() || id.IsZero() || expected < 1 || at.IsZero() || !validTicketAudit(entry) {
		return ticketing.Intent{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.audit == nil {
		return ticketing.Intent{}, fmt.Errorf("%w: ticket audit logger required", shared.ErrValidation)
	}
	current, ok := s.intents[tenant][id]
	if !ok {
		return ticketing.Intent{}, shared.ErrNotFound
	}
	if current.Version != expected || (current.State != writeintent.Failed && current.State != writeintent.Uncertain) {
		return ticketing.Intent{}, shared.ErrConflict
	}
	for _, item := range s.intents[tenant] {
		if item.ID != current.ID && item.IntegrationID == current.IntegrationID && item.FindingID == current.FindingID &&
			item.Action == ticketing.Create && (item.State == writeintent.Pending || item.State == writeintent.InFlight || item.State == writeintent.Uncertain) {
			return ticketing.Intent{}, shared.ErrConflict
		}
	}
	tuple, err := current.DispatchTarget()
	if err != nil {
		return ticketing.Intent{}, err
	}
	b := s.breakers[ticketBreakerKey(tuple)]
	if (b.code == "rate_limited" || b.code == "http_429") && b.gate != nil && at.Before(*b.gate) {
		return ticketing.Intent{}, shared.ErrConflict
	}
	event := writeintent.RetryFailed
	if current.State == writeintent.Uncertain {
		event = writeintent.ReconcileAbsent
	}
	next, err := current.Apply(ticketing.IntentTransition{Event: event}, at)
	if err != nil {
		return ticketing.Intent{}, err
	}
	if err = s.audit.Record(shared.WithTenant(ctx, tenant), entry); err != nil {
		return ticketing.Intent{}, err
	}
	s.intents[tenant][id] = next.Clone()
	b.gate, b.code = nil, ""
	s.breakers[ticketBreakerKey(tuple)] = b
	return next.Clone(), nil
}
