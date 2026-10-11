package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.NotificationEventReader = (*NotificationRepository)(nil)

// maxRecentNotificationEvents bounds one ListRecentNotificationEvents call.
const maxRecentNotificationEvents = 100

const notificationEventSelect = `SELECT id,event_type,source_kind,source_id,engagement_id,severity,schema_version,occurred_at,data,subject_kind,subject_id,context FROM notification_events`

func scanNotificationEvent(row pgx.Row, tenant shared.ID) (notification.Event, error) {
	var (
		e         notification.Event
		eventType string
		data      []byte
		context   []byte
	)
	if err := row.Scan(&e.ID, &eventType, &e.SourceKind, &e.SourceID, &e.EngagementID, &e.Severity, &e.SchemaVersion, &e.OccurredAt, &data, &e.SubjectKind, &e.SubjectID, &context); err != nil {
		return notification.Event{}, err
	}
	e.TenantID, e.Type, e.Data, e.Context = tenant, notification.EventType(eventType), data, context
	return e, nil
}

// ListRecentNotificationEvents returns the tenant's newest events of one type for the template
// preview (#1372). It runs under the tenant's row-level security, and the
// notification_events_type_recent_idx index serves it without scanning the tenant's other events.
func (r *NotificationRepository) ListRecentNotificationEvents(ctx context.Context, tenant shared.ID, eventType notification.EventType, limit int) ([]notification.Event, error) {
	if limit <= 0 || limit > maxRecentNotificationEvents {
		limit = maxRecentNotificationEvents
	}
	out := []notification.Event{}
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, notificationEventSelect+` WHERE tenant_id=$1 AND event_type=$2 ORDER BY occurred_at DESC, id DESC LIMIT $3`, tenant, eventType, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			e, err := scanNotificationEvent(rows, tenant)
			if err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

// GetNotificationEvent returns one of the tenant's events. Another tenant's event is not found.
func (r *NotificationRepository) GetNotificationEvent(ctx context.Context, tenant, id shared.ID) (notification.Event, error) {
	var out notification.Event
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		var err error
		out, err = scanNotificationEvent(tx.QueryRow(ctx, notificationEventSelect+` WHERE tenant_id=$1 AND id=$2`, tenant, id), tenant)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		err = fmt.Errorf("notification event %s: %w", id, shared.ErrNotFound)
	}
	return out, err
}
