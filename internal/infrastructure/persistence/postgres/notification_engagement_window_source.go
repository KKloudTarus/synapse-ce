package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	engagementWindowStartingStateKind = "engagement_window_starting"
	engagementWindowEndingStateKind   = "engagement_window_ending"
	maxEngagementWindowBatch          = 64
)

type engagementWindowRow struct {
	id               shared.ID
	name, status, tz string
	from, to         *time.Time
	leadUserID       shared.ID
	boundary         time.Time
	updatedAt        time.Time
}

func (s *NotificationSource) pollEngagementWindows(ctx context.Context, tx pgx.Tx, tenant shared.ID, activated, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}
	limit = min(limit, maxEngagementWindowBatch)
	type category struct {
		event     notification.EventType
		stateKind string
		column    string
		boundary  string
	}
	categoriesByLead := make([]func(int) (int, error), 0)
	for _, item := range []category{
		{notification.EventEngagementWindowStarting, engagementWindowStartingStateKind, "authorized_from", "authorized_from"},
		{notification.EventEngagementWindowEnding, engagementWindowEndingStateKind, "authorized_to", "authorized_to"},
	} {
		leads, err := engagementWindowLeads(ctx, tx, tenant, item.event)
		if err != nil {
			return 0, err
		}
		for _, lead := range leads {
			entry, seconds := item, lead
			categoriesByLead = append(categoriesByLead, func(budget int) (int, error) {
				return s.pollEngagementWindow(ctx, tx, tenant, activated, now, entry.event, entry.stateKind, entry.column, entry.boundary, seconds, budget)
			})
		}
	}
	return pollNotificationCategories(ctx, tx, tenant, "engagement_window_poll", now, limit, categoriesByLead)
}

func (s *NotificationSource) baselineEngagementWindows(ctx context.Context, tx pgx.Tx, tenant shared.ID, now time.Time) error {
	for _, item := range []struct {
		event     notification.EventType
		stateKind string
		column    string
	}{
		{notification.EventEngagementWindowStarting, engagementWindowStartingStateKind, "authorized_from"},
		{notification.EventEngagementWindowEnding, engagementWindowEndingStateKind, "authorized_to"},
	} {
		leads, err := engagementWindowLeads(ctx, tx, tenant, item.event)
		if err != nil {
			return err
		}
		if len(leads) == 0 {
			continue
		}
		query := `INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at)
			SELECT e.tenant_id,$2,e.id || ':' || ((extract(epoch FROM e.` + item.column + `)*1000000)::bigint)::text || ':' || lead::text,
				e.` + item.column + `::text,true,$3
			FROM engagements e CROSS JOIN unnest($4::bigint[]) lead
			WHERE e.tenant_id=$1 AND e.project_id IS NULL AND e.host_asset_id IS NULL
				AND e.status IN ('draft','active') AND e.` + item.column + ` IS NOT NULL
				AND e.` + item.column + `>$3
				AND e.` + item.column + `<= $3::timestamptz+make_interval(secs=>lead::double precision)
			ON CONFLICT DO NOTHING`
		if _, err := tx.Exec(ctx, query, tenant, item.stateKind, now.UTC(), leads); err != nil {
			return err
		}
	}
	return nil
}

func engagementWindowLeads(ctx context.Context, tx pgx.Tx, tenant shared.ID, event notification.EventType) ([]int64, error) {
	return notificationRuleLeads(ctx, tx, tenant, event)
}

func (s *NotificationSource) pollEngagementWindow(ctx context.Context, tx pgx.Tx, tenant shared.ID, activated, now time.Time, event notification.EventType, stateKind, column, boundaryName string, lead int64, limit int) (int, error) {
	if lead <= 0 || limit <= 0 {
		return 0, nil
	}
	query := `SELECT e.id,e.name,e.status,e.timezone,e.authorized_from,e.authorized_to,
			COALESCE(lead.id,''),e.` + column + `,e.updated_at
		FROM engagements e
		LEFT JOIN notification_engagement_settings settings ON settings.tenant_id=e.tenant_id AND settings.engagement_id=e.id
		LEFT JOIN users lead ON lead.ownership_tenant_id=settings.tenant_id AND lead.id=settings.lead_user_id
			AND NOT lead.disabled AND lead.role=ANY($6)
		LEFT JOIN notification_source_state state ON state.tenant_id=e.tenant_id AND state.source_kind=$3
			AND state.source_id=e.id || ':' || ((extract(epoch FROM e.` + column + `)*1000000)::bigint)::text || ':' || ($4::bigint)::text
		WHERE e.tenant_id=$1 AND e.project_id IS NULL AND e.host_asset_id IS NULL
			AND e.status IN ('draft','active') AND e.` + column + ` IS NOT NULL
			AND e.` + column + `>$2 AND e.` + column + `<=$2::timestamptz+make_interval(secs=>$4::double precision)
			AND state.active IS NOT TRUE
		ORDER BY e.` + column + `,e.id LIMIT $5 FOR UPDATE OF e SKIP LOCKED`
	rows, err := tx.Query(ctx, query, tenant, now.UTC(), stateKind, lead, limit, humanNotificationRoles)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	items := make([]engagementWindowRow, 0, limit)
	for rows.Next() {
		var item engagementWindowRow
		if err := rows.Scan(&item.id, &item.name, &item.status, &item.tz, &item.from, &item.to, &item.leadUserID, &item.boundary, &item.updatedAt); err != nil {
			return 0, err
		}
		if item.from != nil {
			value := item.from.UTC()
			item.from = &value
		}
		if item.to != nil {
			value := item.to.UTC()
			item.to = &value
		}
		item.boundary, item.updatedAt = item.boundary.UTC(), item.updatedAt.UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	count := 0
	for _, item := range items {
		threshold := item.boundary.Add(-time.Duration(lead) * time.Second)
		stateID := engagementWindowStateID(item.id, item.boundary, lead)
		if threshold.Before(activated) && !item.updatedAt.After(activated) {
			if err := upsertLifecycleState(ctx, tx, tenant, stateKind, stateID, item.boundary.Format(time.RFC3339Nano), true, now); err != nil {
				return count, err
			}
			continue
		}
		occurredAt := threshold
		if item.updatedAt.After(occurredAt) {
			occurredAt = item.updatedAt
		}
		if err := publishEngagementWindow(ctx, tx, tenant, event, stateKind, stateID, item, boundaryName, lead, occurredAt); err != nil {
			return count, err
		}
		if err := upsertLifecycleState(ctx, tx, tenant, stateKind, stateID, item.boundary.Format(time.RFC3339Nano), true, now); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func engagementWindowStateID(id shared.ID, boundary time.Time, lead int64) string {
	return id.String() + ":" + strconv.FormatInt(boundary.UTC().UnixMicro(), 10) + ":" + strconv.FormatInt(lead, 10)
}

func publishEngagementWindow(ctx context.Context, tx pgx.Tx, tenant shared.ID, event notification.EventType, sourceKind, sourceID string, item engagementWindowRow, boundaryName string, lead int64, occurredAt time.Time) error {
	title, summary := "Engagement window starting", fmt.Sprintf("The authorization window starts in %s.", time.Duration(lead)*time.Second)
	if event == notification.EventEngagementWindowEnding {
		title, summary = "Engagement window ending", fmt.Sprintf("The authorization window ends in %s.", time.Duration(lead)*time.Second)
	}
	item.name = privacy.ScrubURLCredentials(notification.ScrubPersonalText(item.name, 500))
	item.tz = privacy.ScrubURLCredentials(notification.ScrubPersonalText(item.tz, 100))
	data := map[string]any{
		"title": title, "summary": summary, "engagement_id": item.id, "lead_user_id": item.leadUserID.String(),
		"status": item.status, "timezone": item.tz,
		"boundary": boundaryName, "lead_time_seconds": lead, "engagement_name": item.name, "actor": "system",
	}
	if item.from != nil {
		data["authorized_from"] = *item.from
	}
	if item.to != nil {
		data["authorized_to"] = *item.to
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	label := ""
	if spec, ok := notification.LookupEvent(event); ok {
		label = spec.Label
	}
	vars := map[string]string{
		"event_type": string(event), "event_label": label, "occurred_at": occurredAt.UTC().Format(time.RFC3339),
		"title": title, "summary": summary, "status": item.status, "from_status": "", "to_status": "",
		"timezone": item.tz, "boundary": boundaryName, "lead_time_hours": strconv.FormatFloat(float64(lead)/3600, 'f', -1, 64),
		"engagement_name": item.name, "actor": "system",
	}
	if item.from != nil {
		vars["authorized_from"] = item.from.Format(time.RFC3339)
	}
	if item.to != nil {
		vars["authorized_to"] = item.to.Format(time.RFC3339)
	}
	return appendNotificationSnapshotTx(ctx, tx, notification.SourceRecord{
		TenantID: tenant, SourceKind: sourceKind, SourceID: sourceID, EventType: event,
		EngagementID: item.id, OccurredAt: occurredAt.UTC(), Data: raw, SubjectKind: "engagement", SubjectID: item.id.String(),
	}, vars)
}
