package postgres

import (
	"context"
	"encoding/json"
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

const notificationEventSelect = `SELECT id,event_type,source_kind,source_id,engagement_id,severity,schema_version,occurred_at,data,subject_kind,subject_id,context,test_template FROM notification_events`

func scanNotificationEvent(row pgx.Row, tenant shared.ID) (notification.Event, error) {
	var (
		e         notification.Event
		eventType string
		data      []byte
		context   []byte
		template  []byte
	)
	if err := row.Scan(&e.ID, &eventType, &e.SourceKind, &e.SourceID, &e.EngagementID, &e.Severity, &e.SchemaVersion, &e.OccurredAt, &data, &e.SubjectKind, &e.SubjectID, &context, &template); err != nil {
		return notification.Event{}, err
	}
	e.TenantID, e.Type, e.Data, e.Context = tenant, notification.EventType(eventType), data, context
	version, err := decodeTestTemplate(template)
	if err != nil {
		return notification.Event{}, err
	}
	e.TestTemplate = version
	return e, nil
}

func decodeTestTemplate(raw []byte) (*notification.TemplateVersion, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var version notification.TemplateVersion
	if err := json.Unmarshal(raw, &version); err != nil {
		return nil, fmt.Errorf("decode test template: %w", err)
	}
	version.Fields = notification.CloneFields(version.Fields)
	return &version, nil
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
		for rows.Next() {
			e, err := scanNotificationEvent(rows, tenant)
			if err != nil {
				rows.Close()
				return err
			}
			out = append(out, e)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		return nil
	})
	return out, err
}

// GetNotificationEvent returns one of the tenant's events. Another tenant's event is not found.
func (r *NotificationRepository) GetNotificationEvent(ctx context.Context, tenant, id shared.ID) (notification.Event, error) {
	var out notification.Event
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		var err error
		out, err = scanNotificationEvent(tx.QueryRow(ctx, notificationEventSelect+` WHERE tenant_id=$1 AND id=$2`, tenant, id), tenant)
		if err != nil {
			return err
		}
		return hydrateDigestEvent(ctx, tx, tenant, &out)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		err = fmt.Errorf("notification event %s: %w", id, shared.ErrNotFound)
	}
	return out, err
}

func hydrateDigestEvent(ctx context.Context, tx pgx.Tx, tenant shared.ID, event *notification.Event) error {
	if event.Type != notification.EventDigest || event.SourceKind != "digest" {
		return nil
	}
	var digest notification.DigestData
	if err := json.Unmarshal(event.Data, &digest); err != nil {
		return fmt.Errorf("decode notification digest: %w", err)
	}
	var window digestWindow
	var cadence string
	if err := tx.QueryRow(ctx, `SELECT rule_id,channel_id,cadence,window_start,window_end,chunk FROM notification_digest_windows
		WHERE tenant_id=$1 AND event_id=$2`, tenant, event.ID).Scan(&window.ruleID, &window.channelID, &cadence, &window.start, &window.end, &window.chunk); err != nil {
		return err
	}
	window.cadence = notification.DeliveryCadence(cadence)
	items, err := loadDigestItems(ctx, tx, tenant, window)
	if err != nil {
		return err
	}
	if items == nil {
		items = []notification.DigestItem{}
	}
	event.DigestItems = items
	event.Severity = notification.DigestSeverity(items)
	// Event readers have no destination class. Detail is the most permissive safe
	// descriptor here: it still excludes every current none override. LoadWork
	// replaces it again with the actual channel class before a raw webhook send.
	data, _, err := currentDigestData(items, digest.Cadence, digest.WindowStart, digest.WindowEnd, notification.DataClassDetail)
	if err != nil {
		return err
	}
	event.Data = data
	return nil
}
