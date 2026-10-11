package memory

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Engagement notification overrides (#1360), as postgres.NotificationRepository keeps them. The
// engagement must have been added with AddEngagement.

func (r *NotificationRepository) GetEngagementNotificationSetting(_ context.Context, tenant, engagement shared.ID) (notification.EngagementNotificationSetting, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.engagements[notificationKey{tenant, engagement}] {
		return notification.EngagementNotificationSetting{}, engagementNotFound(engagement)
	}
	if stored, ok := r.engagementSettings[notificationKey{tenant, engagement}]; ok {
		return cloneEngagementSetting(stored), nil
	}
	return notification.EngagementNotificationSetting{TenantID: tenant, EngagementID: engagement, ExternalNotifications: notification.EngagementNotificationsInherit}, nil
}

func (r *NotificationRepository) PutEngagementNotificationSetting(_ context.Context, s notification.EngagementNotificationSetting) (notification.EngagementNotificationSetting, error) {
	if err := s.Validate(); err != nil {
		return notification.EngagementNotificationSetting{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := notificationKey{s.TenantID, s.EngagementID}
	if !r.engagements[key] {
		return notification.EngagementNotificationSetting{}, engagementNotFound(s.EngagementID)
	}
	if r.engagementSettings[key].Revision != s.Revision-1 {
		return notification.EngagementNotificationSetting{}, fmt.Errorf("engagement notification setting revision is stale: %w", shared.ErrConflict)
	}
	r.engagementSettings[key] = cloneEngagementSetting(s)
	if s.ExternalNotifications == notification.EngagementNotificationsNone {
		r.cancelEngagementDeliveries(s.TenantID, s.EngagementID, *s.UpdatedAt)
	}
	return cloneEngagementSetting(s), nil
}

// cancelEngagementDeliveries mirrors the Postgres update: open deliveries about the engagement with
// no attempt in flight are cancelled with engagement_suppressed.
func (r *NotificationRepository) cancelEngagementDeliveries(tenant, engagement shared.ID, at time.Time) {
	for key, stored := range r.deliveries {
		d := stored.delivery
		event, ok := r.events[notificationKey{tenant, d.EventID}]
		if key.tenant != tenant || !ok || event.event.EngagementID != engagement || !openDelivery(d.State) || r.attemptInFlight(key) {
			continue
		}
		d.State, d.LastError, d.NextAttemptAt, d.UpdatedAt = notification.DeliveryCancelled, notification.CodeEngagementSuppressed, nil, at
		stored.delivery = d
		r.deliveries[key] = stored
	}
}

// engagementNotifications is the override LoadWork reports for an event's engagement.
func (r *NotificationRepository) engagementNotifications(tenant, engagement shared.ID) notification.EngagementNotifications {
	if stored, ok := r.engagementSettings[notificationKey{tenant, engagement}]; ok && !engagement.IsZero() {
		return stored.ExternalNotifications
	}
	return notification.EngagementNotificationsInherit
}

func cloneEngagementSetting(s notification.EngagementNotificationSetting) notification.EngagementNotificationSetting {
	s.UpdatedAt = cloneTime(s.UpdatedAt)
	return s
}

func engagementNotFound(id shared.ID) error {
	return fmt.Errorf("engagement %s: %w", id, shared.ErrNotFound)
}
