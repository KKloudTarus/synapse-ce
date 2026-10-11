package memory

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// NotificationSource is the in-memory twin of postgres.NotificationSource. It projects the
// records producers appended to the memory NotificationOutbox into events, through the memory
// repository, following the Postgres poller's rules:
//   - the first poll of a tenant only activates notifications for it, so records dated before
//     that moment are never published;
//   - later polls drain pending records oldest first, within one budget of limit records for the
//     whole tick, and mark each one processed after it is published;
//   - a record whose event the domain refuses is quarantined: it is marked processed, its reason is
//     listed by NotificationRepository.ListSourceFailures, and the records after it still publish.
//
// It drains records of every source kind. The Postgres pollers that scan other tables (SLA
// deadlines, fleet agents, ownership changes, vulnerability actions) and the personal inbox
// retention have no memory counterpart.
type NotificationSource struct {
	repo   *NotificationRepository
	outbox *NotificationOutbox

	mu      sync.Mutex
	tenants map[shared.ID]bool
}

var _ ports.NotificationSource = (*NotificationSource)(nil)

const (
	defaultSourcePollLimit = 100
	maxSourcePollLimit     = 200
	// maxEventDataBytes is the bound notification.Event.Validate puts on event data.
	maxEventDataBytes = 16384
)

func NewNotificationSource(repo *NotificationRepository, outbox *NotificationOutbox) *NotificationSource {
	return &NotificationSource{repo: repo, outbox: outbox, tenants: map[shared.ID]bool{}}
}

// AddTenant makes the source visit a tenant that has no notification configuration or outbox
// activity yet. It stands in for the tenants table the Postgres poller reads.
func (s *NotificationSource) AddTenant(tenant shared.ID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tenants[tenant] = true
}

// Poll projects pending records of every known tenant: tenants added with AddTenant, tenants with
// notification channels or rules, and tenants with outbox activity. A failing tenant does not stop the others.
func (s *NotificationSource) Poll(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		limit = defaultSourcePollLimit
	}
	limit = min(limit, maxSourcePollLimit)
	total := 0
	var failures []error
	for _, tenant := range s.knownTenants() {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		if total >= limit {
			break
		}
		n, err := s.pollTenant(ctx, tenant, now.UTC(), limit-total)
		if err != nil {
			failures = append(failures, fmt.Errorf("poll notification sources for tenant %s: %w", tenant, err))
			continue
		}
		total += n
	}
	return total, errors.Join(failures...)
}

func (s *NotificationSource) pollTenant(ctx context.Context, tenant shared.ID, now time.Time, limit int) (int, error) {
	if !s.outbox.isActivated(tenant) {
		s.outbox.Activate(tenant, now)
		return 0, nil
	}
	records := s.outbox.pending(tenant, limit)
	for _, record := range records {
		event := eventFromSourceRecord(record)
		if _, err := s.repo.Publish(ctx, event); err != nil {
			if !errors.Is(err, shared.ErrValidation) {
				return 0, err
			}
			s.repo.recordSourceFailure(record, now, quarantineReason(event))
		}
		s.outbox.markProcessed(record)
	}
	return len(records), nil
}

// quarantineReason is the fixed reason code the Postgres poller stores in failed_reason.
func quarantineReason(e notification.Event) string {
	if len(e.Data) > maxEventDataBytes {
		return "event_data_too_large"
	}
	return "invalid_event"
}

// eventFromSourceRecord derives the event the Postgres poller derives: its ID is stable in the
// tenant and source key, so replaying a record publishes nothing new.
func eventFromSourceRecord(record notification.SourceRecord) notification.Event {
	return notification.Event{
		TenantID: record.TenantID, ID: notificationStableID(record.TenantID.String(), record.SourceKind, record.SourceID),
		Type: record.EventType, SourceKind: record.SourceKind, SourceID: record.SourceID,
		EngagementID: record.EngagementID, Severity: record.Severity, SchemaVersion: record.SchemaVersion,
		OccurredAt: record.OccurredAt, Data: record.Data,
	}
}

func (s *NotificationSource) knownTenants() []shared.ID {
	s.mu.Lock()
	seen := maps.Clone(s.tenants)
	s.mu.Unlock()
	for _, tenant := range s.outbox.tenants() {
		seen[tenant] = true
	}
	for _, tenant := range s.repo.tenants() {
		seen[tenant] = true
	}
	return sortedTenants(seen)
}

// tenants lists the tenants that configured notification channels or rules.
func (r *NotificationRepository) tenants() []shared.ID {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []shared.ID
	for key := range r.channels {
		out = append(out, key.tenant)
	}
	for key := range r.rules {
		out = append(out, key.tenant)
	}
	return out
}
