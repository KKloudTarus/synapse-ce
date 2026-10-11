package memory

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.NotificationEventReader = (*NotificationRepository)(nil)

// maxRecentNotificationEvents matches the Postgres repository's cap.
const maxRecentNotificationEvents = 100

// ListRecentNotificationEvents mirrors the Postgres reader: the tenant's events of one type, newest
// first by occurrence then ID, at most limit.
func (r *NotificationRepository) ListRecentNotificationEvents(_ context.Context, tenant shared.ID, eventType notification.EventType, limit int) ([]notification.Event, error) {
	if limit <= 0 || limit > maxRecentNotificationEvents {
		limit = maxRecentNotificationEvents
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []notification.Event{}
	for key, stored := range r.events {
		if key.tenant == tenant && stored.event.Type == eventType {
			out = append(out, cloneNotificationEvent(stored.event))
		}
	}
	slices.SortFunc(out, func(a, b notification.Event) int {
		if c := b.OccurredAt.Compare(a.OccurredAt); c != 0 {
			return c
		}
		return strings.Compare(b.ID.String(), a.ID.String())
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// GetNotificationEvent returns one of the tenant's events; another tenant's event is not found.
func (r *NotificationRepository) GetNotificationEvent(_ context.Context, tenant, id shared.ID) (notification.Event, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored, ok := r.events[notificationKey{tenant, id}]
	if !ok {
		return notification.Event{}, fmt.Errorf("notification event %s: %w", id, shared.ErrNotFound)
	}
	return cloneNotificationEvent(stored.event), nil
}
