package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type NotificationRepository struct{ pool *pgxpool.Pool }

func NewNotificationRepository(pool *pgxpool.Pool) *NotificationRepository {
	return &NotificationRepository{pool: pool}
}

var _ ports.NotificationRepository = (*NotificationRepository)(nil)

func (r *NotificationRepository) CreateChannel(ctx context.Context, c notification.Channel, sealed string) (notification.Channel, error) {
	if err := c.Validate(); err != nil {
		return notification.Channel{}, err
	}
	err := WithTenant(ctx, r.pool, c.TenantID.String(), func(tx pgx.Tx) error {
		if err := notificationAdmission(ctx, tx, c.TenantID, "channel", 50); err != nil {
			return err
		}
		if c.Recipients == nil {
			c.Recipients = []string{}
		}
		recipients, _ := json.Marshal(c.Recipients)
		if _, err := tx.Exec(ctx, `INSERT INTO notification_channels(tenant_id,id,name,channel_type,enabled,destination,recipients,revision,secret_version,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, c.TenantID, c.ID, c.Name, c.Type, c.Enabled, c.Destination, recipients, c.Revision, c.SecretVersion, c.CreatedAt, c.UpdatedAt); err != nil {
			return fmt.Errorf("insert notification channel: %w", err)
		}
		_, err := tx.Exec(ctx, `INSERT INTO notification_channel_versions(tenant_id,channel_id,version,sealed_config,created_at) VALUES($1,$2,$3,$4,$5)`, c.TenantID, c.ID, c.SecretVersion, sealed, c.CreatedAt)
		return err
	})
	return c, err
}

func (r *NotificationRepository) UpdateChannel(ctx context.Context, c notification.Channel, sealed string, replace bool) (notification.Channel, error) {
	if err := c.Validate(); err != nil {
		return notification.Channel{}, err
	}
	err := WithTenant(ctx, r.pool, c.TenantID.String(), func(tx pgx.Tx) error {
		var currentVersion int
		if err := tx.QueryRow(ctx, `SELECT secret_version FROM notification_channels WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL AND revision=$3 FOR UPDATE`, c.TenantID, c.ID, c.Revision-1).Scan(&currentVersion); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("notification channel revision is stale: %w", shared.ErrConflict)
			}
			return err
		}
		if replace {
			c.SecretVersion = currentVersion + 1
			if _, err := tx.Exec(ctx, `INSERT INTO notification_channel_versions(tenant_id,channel_id,version,sealed_config,created_at) VALUES($1,$2,$3,$4,$5)`, c.TenantID, c.ID, c.SecretVersion, sealed, c.UpdatedAt); err != nil {
				return err
			}
		} else {
			c.SecretVersion = currentVersion
		}
		if c.Recipients == nil {
			c.Recipients = []string{}
		}
		recipients, _ := json.Marshal(c.Recipients)
		_, err := tx.Exec(ctx, `UPDATE notification_channels SET name=$3,channel_type=$4,enabled=$5,destination=$6,recipients=$7,revision=$8,secret_version=$9,updated_at=$10 WHERE tenant_id=$1 AND id=$2`, c.TenantID, c.ID, c.Name, c.Type, c.Enabled, c.Destination, recipients, c.Revision, c.SecretVersion, c.UpdatedAt)
		if err == nil && !c.Enabled {
			_, err = tx.Exec(ctx, `UPDATE notification_deliveries d SET state='cancelled',last_error='channel_disabled',next_attempt_at=NULL,updated_at=$3 WHERE tenant_id=$1 AND channel_id=$2 AND state IN ('pending','retrying') AND NOT EXISTS(SELECT 1 FROM notification_delivery_attempts a WHERE a.tenant_id=d.tenant_id AND a.delivery_id=d.id AND a.outcome='started')`, c.TenantID, c.ID, c.UpdatedAt)
		}
		return err
	})
	return c, err
}

func (r *NotificationRepository) DeleteChannel(ctx context.Context, tenant, id shared.ID, revision int, at time.Time) error {
	return WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE notification_channels SET enabled=false,deleted_at=$4,updated_at=$4,revision=revision+1 WHERE tenant_id=$1 AND id=$2 AND revision=$3 AND deleted_at IS NULL`, tenant, id, revision, at)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("notification channel revision is stale: %w", shared.ErrConflict)
		}
		_, err = tx.Exec(ctx, `UPDATE notification_deliveries d SET state='cancelled',last_error='channel_deleted',next_attempt_at=NULL,updated_at=$3 WHERE tenant_id=$1 AND channel_id=$2 AND state IN ('pending','retrying') AND NOT EXISTS(SELECT 1 FROM notification_delivery_attempts a WHERE a.tenant_id=d.tenant_id AND a.delivery_id=d.id AND a.outcome='started')`, tenant, id, at)
		return err
	})
}

func (r *NotificationRepository) GetChannel(ctx context.Context, tenant, id shared.ID) (notification.Channel, error) {
	var out notification.Channel
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		var recipients []byte
		var typ string
		err := tx.QueryRow(ctx, channelSelect+` WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL`, tenant, id).Scan(&out.TenantID, &out.ID, &out.Name, &typ, &out.Enabled, &out.Destination, &recipients, &out.Revision, &out.SecretVersion, &out.CreatedAt, &out.UpdatedAt, &out.DeletedAt)
		out.Type = notification.ChannelType(typ)
		if err == nil {
			err = json.Unmarshal(recipients, &out.Recipients)
		}
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		err = fmt.Errorf("notification channel %s: %w", id, shared.ErrNotFound)
	}
	return out, err
}

func (r *NotificationRepository) ListChannels(ctx context.Context, tenant shared.ID) ([]notification.Channel, error) {
	var out []notification.Channel
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, channelSelect+` WHERE tenant_id=$1 AND deleted_at IS NULL ORDER BY name,id`, tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c notification.Channel
			var recipients []byte
			var typ string
			if err := rows.Scan(&c.TenantID, &c.ID, &c.Name, &typ, &c.Enabled, &c.Destination, &recipients, &c.Revision, &c.SecretVersion, &c.CreatedAt, &c.UpdatedAt, &c.DeletedAt); err != nil {
				return err
			}
			c.Type = notification.ChannelType(typ)
			if err := json.Unmarshal(recipients, &c.Recipients); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

const channelSelect = `SELECT tenant_id,id,name,channel_type,enabled,destination,recipients,revision,secret_version,created_at,updated_at,deleted_at FROM notification_channels`

func (r *NotificationRepository) CreateRule(ctx context.Context, rule notification.Rule) (notification.Rule, error) {
	if err := rule.Normalize(); err != nil {
		return notification.Rule{}, err
	}
	err := WithTenant(ctx, r.pool, rule.TenantID.String(), func(tx pgx.Tx) error { return insertRule(ctx, tx, rule, false) })
	return rule, err
}
func (r *NotificationRepository) UpdateRule(ctx context.Context, rule notification.Rule) (notification.Rule, error) {
	if err := rule.Normalize(); err != nil {
		return notification.Rule{}, err
	}
	err := WithTenant(ctx, r.pool, rule.TenantID.String(), func(tx pgx.Tx) error { return insertRule(ctx, tx, rule, true) })
	return rule, err
}
func insertRule(ctx context.Context, tx pgx.Tx, r notification.Rule, update bool) error {
	for _, id := range r.TeamIDs {
		var owned bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ownership_teams WHERE tenant_id=$1 AND id=$2)`, r.TenantID, id).Scan(&owned); err != nil {
			return err
		}
		if !owned {
			return fmt.Errorf("notification team %s: %w", id, shared.ErrNotFound)
		}
	}
	for _, id := range r.EngagementIDs {
		var owned bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM engagements WHERE tenant_id=$1 AND id=$2)`, r.TenantID, id).Scan(&owned); err != nil {
			return err
		}
		if !owned {
			return fmt.Errorf("notification engagement %s: %w", id, shared.ErrNotFound)
		}
	}
	if !update {
		if err := notificationAdmission(ctx, tx, r.TenantID, "rule", 200); err != nil {
			return err
		}
	}
	actions, _ := json.Marshal(r.ActionTypes)
	engs, _ := json.Marshal(r.EngagementIDs)
	if update {
		tag, err := tx.Exec(ctx, `UPDATE notification_rules SET name=$3,enabled=$4,event_type=$5,min_severity=$6,action_types=$7,engagement_ids=$8,lead_time_secs=$9,revision=$10,updated_at=$11,all_teams=$13 WHERE tenant_id=$1 AND id=$2 AND revision=$12`, r.TenantID, r.ID, r.Name, r.Enabled, r.EventType, r.MinSeverity, actions, engs, r.LeadTimeSecs, r.Revision, r.UpdatedAt, r.Revision-1, r.AllTeams)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("notification rule revision is stale: %w", shared.ErrConflict)
		}
		if _, err = tx.Exec(ctx, `DELETE FROM notification_rule_channels WHERE tenant_id=$1 AND rule_id=$2`, r.TenantID, r.ID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM notification_rule_teams WHERE tenant_id=$1 AND rule_id=$2`, r.TenantID, r.ID); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(ctx, `INSERT INTO notification_rules(tenant_id,id,name,enabled,event_type,min_severity,action_types,engagement_ids,lead_time_secs,revision,created_at,updated_at,all_teams) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, r.TenantID, r.ID, r.Name, r.Enabled, r.EventType, r.MinSeverity, actions, engs, r.LeadTimeSecs, r.Revision, r.CreatedAt, r.UpdatedAt, r.AllTeams); err != nil {
			return err
		}
	}
	for _, id := range r.TeamIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO notification_rule_teams(tenant_id,rule_id,team_id) VALUES($1,$2,$3)`, r.TenantID, r.ID, id); err != nil {
			return err
		}
	}
	for _, cid := range r.ChannelIDs {
		tag, err := tx.Exec(ctx, `INSERT INTO notification_rule_channels(tenant_id,rule_id,channel_id) SELECT $1,$2,id FROM notification_channels WHERE tenant_id=$1 AND id=$3 AND deleted_at IS NULL`, r.TenantID, r.ID, cid)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("notification channel %s: %w", cid, shared.ErrNotFound)
		}
	}
	return nil
}
func (r *NotificationRepository) DeleteRule(ctx context.Context, tenant, id shared.ID, revision int) error {
	return WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM notification_rules WHERE tenant_id=$1 AND id=$2 AND revision=$3`, tenant, id, revision)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("notification rule revision is stale: %w", shared.ErrConflict)
		}
		return nil
	})
}
func (r *NotificationRepository) GetRule(ctx context.Context, tenant, id shared.ID) (notification.Rule, error) {
	var out notification.Rule
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		return scanRule(tx.QueryRow(ctx, ruleSelect+` WHERE r.tenant_id=$1 AND r.id=$2 GROUP BY r.tenant_id,r.id`, tenant, id), &out)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		err = fmt.Errorf("notification rule %s: %w", id, shared.ErrNotFound)
	}
	return out, err
}
func (r *NotificationRepository) ListRules(ctx context.Context, tenant shared.ID) ([]notification.Rule, error) {
	var out []notification.Rule
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, ruleSelect+` WHERE r.tenant_id=$1 GROUP BY r.tenant_id,r.id ORDER BY r.name,r.id`, tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v notification.Rule
			if err := scanRule(rows, &v); err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, err
}

const ruleSelect = `SELECT r.tenant_id,r.id,r.name,r.enabled,r.event_type,r.min_severity,r.action_types,r.engagement_ids,r.lead_time_secs,r.revision,r.created_at,r.updated_at,COALESCE(jsonb_agg(rc.channel_id ORDER BY rc.channel_id) FILTER(WHERE rc.channel_id IS NOT NULL),'[]'),r.all_teams,COALESCE((SELECT jsonb_agg(rt.team_id ORDER BY rt.team_id) FROM notification_rule_teams rt WHERE rt.tenant_id=r.tenant_id AND rt.rule_id=r.id),'[]') FROM notification_rules r LEFT JOIN notification_rule_channels rc ON rc.tenant_id=r.tenant_id AND rc.rule_id=r.id`

type scanner interface{ Scan(...any) error }

func scanRule(row scanner, out *notification.Rule) error {
	var typ string
	var actions, engs, channels, teams []byte
	if err := row.Scan(&out.TenantID, &out.ID, &out.Name, &out.Enabled, &typ, &out.MinSeverity, &actions, &engs, &out.LeadTimeSecs, &out.Revision, &out.CreatedAt, &out.UpdatedAt, &channels, &out.AllTeams, &teams); err != nil {
		return err
	}
	out.EventType = notification.EventType(typ)
	out.LeadTime = time.Duration(out.LeadTimeSecs) * time.Second
	if err := json.Unmarshal(actions, &out.ActionTypes); err != nil {
		return err
	}
	if err := json.Unmarshal(engs, &out.EngagementIDs); err != nil {
		return err
	}
	if err := json.Unmarshal(teams, &out.TeamIDs); err != nil {
		return err
	}
	return json.Unmarshal(channels, &out.ChannelIDs)
}

func (r *NotificationRepository) Publish(ctx context.Context, e notification.Event) ([]shared.ID, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	var ids []shared.ID
	err := WithTenant(ctx, r.pool, e.TenantID.String(), func(tx pgx.Tx) error { var err error; ids, err = r.publishTx(ctx, tx, e, shared.ID("")); return err })
	return ids, err
}
func (r *NotificationRepository) PublishToChannel(ctx context.Context, e notification.Event, cid shared.ID) (shared.ID, error) {
	if err := e.Validate(); err != nil {
		return "", err
	}
	var ids []shared.ID
	err := WithTenant(ctx, r.pool, e.TenantID.String(), func(tx pgx.Tx) error {
		if e.Type == notification.EventTest {
			var locked shared.ID
			if err := tx.QueryRow(ctx, `SELECT id FROM notification_channels WHERE tenant_id=$1 AND id=$2 AND enabled AND deleted_at IS NULL FOR UPDATE`, e.TenantID, cid).Scan(&locked); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return fmt.Errorf("notification channel %s: %w", cid, shared.ErrNotFound)
				}
				return err
			}
			var recent int
			if err := tx.QueryRow(ctx, `SELECT count(DISTINCT d.event_id) FROM notification_deliveries d JOIN notification_events e ON e.tenant_id=d.tenant_id AND e.id=d.event_id WHERE d.tenant_id=$1 AND d.channel_id=$2 AND e.event_type='notification.test' AND d.created_at >= now()-interval '1 minute'`, e.TenantID, cid).Scan(&recent); err != nil {
				return err
			}
			if recent >= 10 {
				return fmt.Errorf("notification channel test rate limit exceeded: %w", shared.ErrSaturated)
			}
		}
		var err error
		ids, err = r.publishTx(ctx, tx, e, cid)
		return err
	})
	if err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("notification channel %s: %w", cid, shared.ErrNotFound)
	}
	return ids[0], nil
}
func (r *NotificationRepository) publishTx(ctx context.Context, tx pgx.Tx, e notification.Event, only shared.ID) ([]shared.ID, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	data := []byte(e.Data)
	tag, err := tx.Exec(ctx, `INSERT INTO notification_events(tenant_id,id,event_type,source_kind,source_id,engagement_id,severity,schema_version,occurred_at,data) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(tenant_id,source_kind,source_id) DO NOTHING`, e.TenantID, e.ID, e.Type, e.SourceKind, e.SourceID, e.EngagementID, e.Severity, e.SchemaVersion, e.OccurredAt, data)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		var existing shared.ID
		if err := tx.QueryRow(ctx, `SELECT id FROM notification_events WHERE tenant_id=$1 AND source_kind=$2 AND source_id=$3`, e.TenantID, e.SourceKind, e.SourceID).Scan(&existing); err != nil {
			return nil, err
		}
		rows, err := tx.Query(ctx, `SELECT id FROM notification_deliveries WHERE tenant_id=$1 AND event_id=$2 ORDER BY id`, e.TenantID, existing)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var ids []shared.ID
		for rows.Next() {
			var id shared.ID
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
		return ids, rows.Err()
	}

	type target struct {
		channel notification.Channel
		rules   []shared.ID
	}
	targets := map[shared.ID]*target{}
	revisions := map[shared.ID]int{}
	if !only.IsZero() {
		var c notification.Channel
		var recipients []byte
		var typ string
		if err := tx.QueryRow(ctx, channelSelect+` WHERE tenant_id=$1 AND id=$2 AND enabled AND deleted_at IS NULL`, e.TenantID, only).Scan(&c.TenantID, &c.ID, &c.Name, &typ, &c.Enabled, &c.Destination, &recipients, &c.Revision, &c.SecretVersion, &c.CreatedAt, &c.UpdatedAt, &c.DeletedAt); err != nil {
			return nil, err
		}
		c.Type = notification.ChannelType(typ)
		_ = json.Unmarshal(recipients, &c.Recipients)
		targets[c.ID] = &target{channel: c}
	} else {
		rows, err := tx.Query(ctx, ruleSelect+` WHERE r.tenant_id=$1 AND r.enabled AND r.event_type=$2 GROUP BY r.tenant_id,r.id`, e.TenantID, e.Type)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var rule notification.Rule
			if err := scanRule(rows, &rule); err != nil {
				rows.Close()
				return nil, err
			}
			if rule.Matches(e) {
				revisions[rule.ID] = rule.Revision
				for _, cid := range rule.ChannelIDs {
					t := targets[cid]
					if t == nil {
						t = &target{}
						targets[cid] = t
					}
					t.rules = append(t.rules, rule.ID)
				}
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
		for cid, t := range targets {
			var recipients []byte
			var typ string
			if err := tx.QueryRow(ctx, channelSelect+` WHERE tenant_id=$1 AND id=$2 AND enabled AND deleted_at IS NULL`, e.TenantID, cid).Scan(&t.channel.TenantID, &t.channel.ID, &t.channel.Name, &typ, &t.channel.Enabled, &t.channel.Destination, &recipients, &t.channel.Revision, &t.channel.SecretVersion, &t.channel.CreatedAt, &t.channel.UpdatedAt, &t.channel.DeletedAt); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					delete(targets, cid)
					continue
				}
				return nil, err
			}
			t.channel.Type = notification.ChannelType(typ)
			_ = json.Unmarshal(recipients, &t.channel.Recipients)
		}
	}
	allRules := []shared.ID{}
	ids := []shared.ID{}
	if len(targets) > 0 {
		if err := notificationAdmission(ctx, tx, e.TenantID, "delivery", 10000); err != nil {
			return nil, err
		}
	}
	for _, t := range targets {
		recipients := []string{""}
		if t.channel.Type == notification.ChannelEmail {
			recipients = t.channel.Recipients
		}
		for _, recipient := range recipients {
			did := stableID(e.TenantID.String(), e.ID.String(), t.channel.ID.String(), strings.ToLower(recipient))
			if t.rules == nil {
				t.rules = []shared.ID{}
			}
			rules, _ := json.Marshal(t.rules)
			created := time.Now().UTC()
			tag, err := tx.Exec(ctx, `INSERT INTO notification_deliveries(tenant_id,id,event_id,channel_id,channel_version,channel_type,recipient,matched_rules,state,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,$9) ON CONFLICT(tenant_id,event_id,channel_id,recipient) DO NOTHING`, e.TenantID, did, e.ID, t.channel.ID, t.channel.SecretVersion, t.channel.Type, recipient, rules, created)
			if err != nil {
				return nil, err
			}
			if tag.RowsAffected() > 0 {
				payload, _ := json.Marshal(map[string]string{"delivery_id": did.String()})
				jobID := "notification-" + did.String()
				if _, err := tx.Exec(ctx, `INSERT INTO jobs(id,tenant_id,kind,payload,status,available_at) VALUES($1,$2,'notification.deliver',$3,'queued',$4) ON CONFLICT(id) DO NOTHING`, jobID, e.TenantID, payload, created); err != nil {
					return nil, err
				}
				ids = append(ids, did)
			}
		}
		allRules = append(allRules, t.rules...)
	}
	matched, _ := json.Marshal(allRules)
	revisionJSON, _ := json.Marshal(revisions)
	_, err = tx.Exec(ctx, `UPDATE notification_events SET matched_rules=$3,rule_revisions=$4 WHERE tenant_id=$1 AND id=$2`, e.TenantID, e.ID, matched, revisionJSON)
	return ids, err
}

func (r *NotificationRepository) GetDelivery(ctx context.Context, tenant, id shared.ID) (notification.Delivery, error) {
	var out notification.Delivery
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		return scanDelivery(tx.QueryRow(ctx, deliverySelect+` WHERE tenant_id=$1 AND id=$2`, tenant, id), &out)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		err = fmt.Errorf("notification delivery %s: %w", id, shared.ErrNotFound)
	}
	return out, err
}
func (r *NotificationRepository) ListDeliveries(ctx context.Context, f ports.NotificationDeliveryFilter) (notification.Page, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	if f.Limit > 200 {
		f.Limit = 200
	}
	var out notification.Page
	err := WithTenant(ctx, r.pool, f.TenantID.String(), func(tx pgx.Tx) error {
		args := []any{f.TenantID}
		where := ` WHERE tenant_id=$1`
		if !f.From.IsZero() {
			args = append(args, f.From)
			where += fmt.Sprintf(" AND created_at >= $%d", len(args))
		}
		if !f.Until.IsZero() {
			args = append(args, f.Until)
			where += fmt.Sprintf(" AND created_at <= $%d", len(args))
		}
		if !f.ChannelID.IsZero() {
			args = append(args, f.ChannelID)
			where += fmt.Sprintf(" AND channel_id=$%d", len(args))
		}
		if f.EventType != "" {
			args = append(args, f.EventType)
			where += fmt.Sprintf(" AND event_id IN (SELECT id FROM notification_events WHERE tenant_id=$1 AND event_type=$%d)", len(args))
		}
		if f.State != "" {
			args = append(args, f.State)
			where += fmt.Sprintf(" AND state=$%d", len(args))
		}
		if !f.Before.IsZero() {
			args = append(args, f.Before, f.BeforeID)
			where += fmt.Sprintf(" AND (created_at,id)<($%d,$%d)", len(args)-1, len(args))
		}
		args = append(args, f.Limit+1)
		rows, err := tx.Query(ctx, deliverySelect+where+fmt.Sprintf(" ORDER BY created_at DESC,id DESC LIMIT $%d", len(args)), args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d notification.Delivery
			if err := scanDelivery(rows, &d); err != nil {
				return err
			}
			out.Items = append(out.Items, d)
		}
		if len(out.Items) > f.Limit {
			last := out.Items[f.Limit-1]
			out.Items = out.Items[:f.Limit]
			out.Next = last.CreatedAt.UTC().Format(time.RFC3339Nano) + "|" + last.ID.String()
		}
		return rows.Err()
	})
	return out, err
}

const deliverySelect = `SELECT tenant_id,id,event_id,channel_id,channel_type,recipient,matched_rules,state,attempts,last_error,next_attempt_at,delivered_at,created_at,updated_at FROM notification_deliveries`

func scanDelivery(row scanner, d *notification.Delivery) error {
	var rules []byte
	var typ, state string
	if err := row.Scan(&d.TenantID, &d.ID, &d.EventID, &d.ChannelID, &typ, &d.Recipient, &rules, &state, &d.Attempts, &d.LastError, &d.NextAttemptAt, &d.DeliveredAt, &d.CreatedAt, &d.UpdatedAt); err != nil {
		return err
	}
	d.ChannelType = notification.ChannelType(typ)
	d.State = notification.DeliveryState(state)
	return json.Unmarshal(rules, &d.MatchedRuleIDs)
}
func (r *NotificationRepository) ListAttempts(ctx context.Context, tenant, did shared.ID) ([]notification.Attempt, error) {
	if _, err := r.GetDelivery(ctx, tenant, did); err != nil {
		return nil, err
	}
	var out []notification.Attempt
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id,delivery_id,attempt_number,started_at,finished_at,outcome,response_code,error_code FROM notification_delivery_attempts WHERE tenant_id=$1 AND delivery_id=$2 ORDER BY attempt_number`, tenant, did)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a notification.Attempt
			if err := rows.Scan(&a.ID, &a.DeliveryID, &a.Number, &a.StartedAt, &a.FinishedAt, &a.Outcome, &a.ResponseCode, &a.ErrorCode); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

func (r *NotificationRepository) LoadWork(ctx context.Context, tenant, did shared.ID) (ports.NotificationWork, error) {
	var w ports.NotificationWork
	var rules, eventData, recipients []byte
	var ctyp, state, etype string
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT d.tenant_id,d.id,d.event_id,d.channel_id,d.channel_type,d.recipient,d.matched_rules,d.state,d.attempts,d.last_error,d.next_attempt_at,d.delivered_at,d.created_at,d.updated_at,e.event_type,e.source_kind,e.source_id,e.engagement_id,e.severity,e.schema_version,e.occurred_at,e.data,c.name,c.enabled,c.destination,c.recipients,c.revision,d.channel_version,c.created_at,c.updated_at,v.sealed_config FROM notification_deliveries d JOIN notification_events e ON e.tenant_id=d.tenant_id AND e.id=d.event_id JOIN notification_channels c ON c.tenant_id=d.tenant_id AND c.id=d.channel_id JOIN notification_channel_versions v ON v.tenant_id=d.tenant_id AND v.channel_id=d.channel_id AND v.version=d.channel_version WHERE d.tenant_id=$1 AND d.id=$2`, tenant, did).Scan(&w.Delivery.TenantID, &w.Delivery.ID, &w.Delivery.EventID, &w.Delivery.ChannelID, &ctyp, &w.Delivery.Recipient, &rules, &state, &w.Delivery.Attempts, &w.Delivery.LastError, &w.Delivery.NextAttemptAt, &w.Delivery.DeliveredAt, &w.Delivery.CreatedAt, &w.Delivery.UpdatedAt, &etype, &w.Event.SourceKind, &w.Event.SourceID, &w.Event.EngagementID, &w.Event.Severity, &w.Event.SchemaVersion, &w.Event.OccurredAt, &eventData, &w.Channel.Name, &w.Channel.Enabled, &w.Channel.Destination, &recipients, &w.Channel.Revision, &w.Channel.SecretVersion, &w.Channel.CreatedAt, &w.Channel.UpdatedAt, &w.Sealed)
	})
	w.Delivery.ChannelType = notification.ChannelType(ctyp)
	w.Delivery.State = notification.DeliveryState(state)
	w.Event.TenantID = tenant
	w.Event.ID = w.Delivery.EventID
	w.Event.Type = notification.EventType(etype)
	w.Event.Data = eventData
	w.Channel.TenantID = tenant
	w.Channel.ID = w.Delivery.ChannelID
	w.Channel.Type = w.Delivery.ChannelType
	_ = json.Unmarshal(rules, &w.Delivery.MatchedRuleIDs)
	_ = json.Unmarshal(recipients, &w.Channel.Recipients)
	if errors.Is(err, pgx.ErrNoRows) {
		err = fmt.Errorf("notification delivery %s: %w", did, shared.ErrNotFound)
	}
	return w, err
}

func (r *NotificationRepository) DeliveryStillRelevant(ctx context.Context, work ports.NotificationWork) (bool, error) {
	switch work.Event.Type {
	case notification.EventSLAApproaching:
		var data struct {
			AssessmentID string    `json:"assessment_id"`
			EngagementID string    `json:"engagement_id"`
			FindingID    string    `json:"finding_id"`
			Deadline     time.Time `json:"deadline"`
		}
		if err := json.Unmarshal(work.Event.Data, &data); err != nil {
			return false, fmt.Errorf("decode SLA notification event: %w", err)
		}
		var relevant bool
		err := WithTenant(ctx, r.pool, work.Event.TenantID.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sla_current_assessments ca JOIN sla_assessments a ON a.tenant_id=ca.tenant_id AND a.id=ca.assessment_id JOIN sla_lifecycles l ON l.tenant_id=ca.tenant_id AND l.engagement_id=ca.engagement_id AND l.finding_id=ca.finding_id WHERE ca.tenant_id=$1 AND ca.engagement_id=$2 AND ca.finding_id=$3 AND ca.assessment_id=$4 AND a.remediate_by=$5 AND a.remediate_by>now() AND a.tier<>'exception' AND l.status IN ('open','mitigating'))`, work.Event.TenantID, data.EngagementID, data.FindingID, data.AssessmentID, data.Deadline).Scan(&relevant)
		})
		return relevant, err
	case notification.EventFleetAgentOffline:
		var data struct {
			AgentID  string    `json:"agent_id"`
			LastSeen time.Time `json:"last_seen_at"`
		}
		if err := json.Unmarshal(work.Event.Data, &data); err != nil {
			return false, fmt.Errorf("decode fleet notification event: %w", err)
		}
		var relevant bool
		err := WithTenant(ctx, r.pool, work.Event.TenantID.String(), func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM fleet_agents WHERE tenant_id=$1 AND id=$2 AND state IN ('active','stale') AND last_seen_at=$3)`, work.Event.TenantID, data.AgentID, data.LastSeen).Scan(&relevant)
		})
		return relevant, err
	default:
		return true, nil
	}
}

func (r *NotificationRepository) BeginAttempt(ctx context.Context, tenant, did shared.ID, jobID string, fence int64, aid shared.ID, at time.Time) (notification.Attempt, error) {
	var out notification.Attempt
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		var ok int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM jobs WHERE tenant_id=$1 AND id=$2 AND kind='notification.deliver' AND status='claimed' AND claim_fence=$3 AND claimed_until>now() FOR UPDATE`, tenant, jobID, fence).Scan(&ok); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ports.ErrStaleLease
			}
			return err
		}
		var n int
		// A shared tenant row serializes this budget across every worker and channel.
		if _, err := tx.Exec(ctx, `INSERT INTO notification_source_state(tenant_id,source_kind,source_id,fingerprint,active,observed_at) VALUES($1,'delivery_rate','tenant','',true,$2::timestamptz-interval '1 second') ON CONFLICT DO NOTHING`, tenant, at); err != nil {
			return err
		}
		var tenantLast time.Time
		if err := tx.QueryRow(ctx, `SELECT observed_at FROM notification_source_state WHERE tenant_id=$1 AND source_kind='delivery_rate' AND source_id='tenant' FOR UPDATE`, tenant).Scan(&tenantLast); err != nil {
			return err
		}
		if at.Sub(tenantLast) < 100*time.Millisecond {
			return fmt.Errorf("%w: tenant rate limited", ports.ErrRetryable)
		}
		var enabled bool
		var last *time.Time
		if err := tx.QueryRow(ctx, `SELECT enabled AND deleted_at IS NULL,last_attempt_at FROM notification_channels WHERE tenant_id=$1 AND id=(SELECT channel_id FROM notification_deliveries WHERE tenant_id=$1 AND id=$2) FOR UPDATE`, tenant, did).Scan(&enabled, &last); err != nil {
			return err
		}
		if !enabled {
			return fmt.Errorf("%w: channel disabled", ports.ErrRetryable)
		}
		if last != nil && at.Sub(*last) < time.Second {
			return fmt.Errorf("%w: channel rate limited", ports.ErrRetryable)
		}
		if _, err := tx.Exec(ctx, `UPDATE notification_source_state SET observed_at=$2 WHERE tenant_id=$1 AND source_kind='delivery_rate' AND source_id='tenant'`, tenant, at); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE notification_channels SET last_attempt_at=$3 WHERE tenant_id=$1 AND id=(SELECT channel_id FROM notification_deliveries WHERE tenant_id=$1 AND id=$2)`, tenant, did, at); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `UPDATE notification_deliveries SET attempts=attempts+1,updated_at=$3 WHERE tenant_id=$1 AND id=$2 AND state IN ('pending','retrying') RETURNING attempts`, tenant, did, at).Scan(&n); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("notification delivery is terminal: %w", shared.ErrConflict)
			}
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO notification_delivery_attempts(tenant_id,id,delivery_id,attempt_number,started_at,outcome) VALUES($1,$2,$3,$4,$5,'started')`, tenant, aid, did, n, at); err != nil {
			return err
		}
		out = notification.Attempt{ID: aid, DeliveryID: did, Number: n, StartedAt: at, Outcome: "started"}
		return nil
	})
	return out, err
}

func (r *NotificationRepository) FinishAttempt(ctx context.Context, tenant, did shared.ID, jobID string, fence int64, aid shared.ID, at time.Time, outcome string, status int, errorCode string, next *time.Time) error {
	if outcome != "delivered" && outcome != "retrying" && outcome != "failed" && outcome != "cancelled" {
		return fmt.Errorf("%w: invalid notification attempt outcome", shared.ErrValidation)
	}
	return WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		var ok int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM jobs WHERE tenant_id=$1 AND id=$2 AND kind='notification.deliver' AND status='claimed' AND claim_fence=$3 AND claimed_until>now() FOR UPDATE`, tenant, jobID, fence).Scan(&ok); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ports.ErrStaleLease
			}
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE notification_delivery_attempts SET finished_at=$4,outcome=$5,response_code=$6,error_code=$7 WHERE tenant_id=$1 AND delivery_id=$2 AND id=$3 AND outcome='started'`, tenant, did, aid, at, outcome, status, errorCode)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("notification attempt %s: %w", aid, shared.ErrConflict)
		}
		state := notification.DeliveryState(outcome)
		if outcome == "failed" {
			state = notification.DeliveryDead
		}
		var delivered *time.Time
		if outcome == "delivered" {
			state = notification.DeliverySucceeded
			delivered = &at
		}
		last := errorCode
		if outcome == "delivered" {
			last = ""
		}
		tag, err = tx.Exec(ctx, `UPDATE notification_deliveries SET state=$3,last_error=$4,next_attempt_at=$5,delivered_at=$6,updated_at=$7 WHERE tenant_id=$1 AND id=$2 AND state IN ('pending','retrying')`, tenant, did, state, last, next, delivered, at)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("notification delivery %s: %w", did, shared.ErrConflict)
		}
		_, err = tx.Exec(ctx, `INSERT INTO notification_audit_intents(tenant_id,id,delivery_id,action,error_code,occurred_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, tenant, aid, did, "notification.delivery_"+outcome, errorCode, at)
		return err
	})
}

func (r *NotificationRepository) CancelDelivery(ctx context.Context, tenant, did shared.ID, jobID string, fence int64, reason string) error {
	return WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		var ok int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM jobs WHERE tenant_id=$1 AND id=$2 AND status='claimed' AND claim_fence=$3 AND claimed_until>now() FOR UPDATE`, tenant, jobID, fence).Scan(&ok); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ports.ErrStaleLease
			}
			return err
		}
		_, err := tx.Exec(ctx, `WITH changed AS (UPDATE notification_deliveries SET state='cancelled',last_error=$3,next_attempt_at=NULL,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND state IN ('pending','retrying') RETURNING id)
        INSERT INTO notification_audit_intents(tenant_id,id,delivery_id,action,error_code,occurred_at) SELECT $1,'cancel:'||id,id,'notification.delivery_cancelled',$3,now() FROM changed ON CONFLICT DO NOTHING`, tenant, did, sanitizeError(reason))
		return err
	})
}

func (r *NotificationRepository) DeadLetterDelivery(ctx context.Context, tenant, did shared.ID, reason string) error {
	return WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `WITH changed AS (UPDATE notification_deliveries d SET state='dead_letter',last_error=$3,next_attempt_at=NULL,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND state IN ('pending','retrying') AND EXISTS(SELECT 1 FROM jobs j WHERE j.tenant_id=d.tenant_id AND j.id='notification-'||d.id AND j.status='failed') RETURNING id)
        INSERT INTO notification_audit_intents(tenant_id,id,delivery_id,action,error_code,occurred_at) SELECT $1,'dead:'||id,id,'notification.delivery_failed',$3,now() FROM changed ON CONFLICT DO NOTHING`, tenant, did, sanitizeError(reason))
		return err
	})
}

func stableID(parts ...string) shared.ID {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return shared.ID(hex.EncodeToString(h[:16]))
}
func sanitizeError(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 160 {
		v = v[:160]
	}
	return v
}
