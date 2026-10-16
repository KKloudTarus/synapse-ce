package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var (
	_ ports.PersonalDeliveryStore = (*InboxStore)(nil)
	_ ports.PersonalDefaultsStore = (*InboxStore)(nil)
)

// LoadPersonalDelivery rechecks a queued personal message at send time (#1418): the inbox row
// still exists, the person is enabled with a human role, their preference or the tenant default
// still allows the channel, the engagement still lets messages leave Synapse and at which data
// class (#1360, read under the lock its setting writes take), and the exact contact version the
// job was queued for is still verified. Any change returns ok=false; a job is never re-pointed at another contact.
func (s *InboxStore) LoadPersonalDelivery(ctx context.Context, tenant, user, event, contact shared.ID, version int, channel string) (ports.PersonalMessage, bool, error) {
	if channel != notification.PersonalEmail && channel != notification.PersonalSlack && channel != notification.PersonalTeams {
		return ports.PersonalMessage{}, false, fmt.Errorf("%w: unknown personal channel", shared.ErrValidation)
	}
	out := ports.PersonalMessage{TenantID: tenant, UserID: user, EventID: event, Channel: channel, ContactID: contact}
	ok := false
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		var state, inApp *string
		var eventType, userRole string
		var recipientRoles []string
		scanErr := tx.QueryRow(ctx, `SELECT n.title, n.summary, n.link_path, n.event_type, p.state, i.state, u.role, n.recipient_roles
			FROM user_notifications n
			JOIN users u ON u.ownership_tenant_id=n.tenant_id AND u.id=n.user_id AND NOT u.disabled AND u.role = ANY($4)
			LEFT JOIN user_notification_preferences p ON p.tenant_id=n.tenant_id AND p.user_id=n.user_id AND p.event_type=n.event_type AND p.channel=$5
			LEFT JOIN user_notification_preferences i ON i.tenant_id=n.tenant_id AND i.user_id=n.user_id AND i.event_type=n.event_type AND i.channel='in_app'
			WHERE n.tenant_id=$1 AND n.user_id=$2 AND n.event_id=$3`, tenant, user, event, humanNotificationRoles, channel).Scan(&out.Title, &out.Summary, &out.LinkPath, &eventType, &state, &inApp, &userRole, &recipientRoles)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		out.EventType = notification.EventType(eventType)
		if !personalRecipientAuthorized(out.EventType, recipientRoles, userRole) {
			return nil
		}
		// Every personal message is sent from its inbox row, so muting the inbox mutes it too, even
		// after it was queued; a mandatory notice cannot be muted.
		inAppChoice := notification.PreferenceInherit
		if inApp != nil {
			inAppChoice = notification.Preference(*inApp)
		}
		if !notification.Deliver(notification.InAppMandatory(out.EventType), inAppChoice, true) {
			return nil
		}
		choice := notification.PreferenceInherit
		if state != nil {
			choice = notification.Preference(*state)
		}
		defaults, err := loadPersonalDefaults(ctx, tx, tenant, out.EventType)
		if err != nil {
			return err
		}
		if !notification.Deliver(false, choice, defaults.Enabled(out.EventType, channel)) {
			return nil
		}
		var engagement *string
		if scanErr = tx.QueryRow(ctx, `SELECT engagement_id FROM notification_events WHERE tenant_id=$1 AND id=$2`, tenant, event).Scan(&engagement); scanErr != nil && !errors.Is(scanErr, pgx.ErrNoRows) {
			return scanErr
		}
		if out.EventType == notification.EventEngagementWindowStarting || out.EventType == notification.EventEngagementWindowEnding {
			var raw json.RawMessage
			if err := tx.QueryRow(ctx, `SELECT data FROM notification_events WHERE tenant_id=$1 AND id=$2`, tenant, event).Scan(&raw); err != nil {
				return err
			}
			var data struct {
				EngagementID string     `json:"engagement_id"`
				Boundary     string     `json:"boundary"`
				From         *time.Time `json:"authorized_from"`
				To           *time.Time `json:"authorized_to"`
			}
			if err := json.Unmarshal(raw, &data); err != nil {
				return err
			}
			column, boundary := "authorized_from", data.From
			if out.EventType == notification.EventEngagementWindowEnding {
				column, boundary = "authorized_to", data.To
			}
			if boundary == nil || data.Boundary != column || engagement == nil || data.EngagementID != *engagement {
				return nil
			}
			var relevant bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM engagements WHERE tenant_id=$1 AND id=$2 AND project_id IS NULL AND host_asset_id IS NULL AND status IN ('draft','active') AND `+column+`=$3 AND `+column+`>now())`, tenant, *engagement, *boundary).Scan(&relevant); err != nil {
				return err
			}
			if !relevant {
				return nil
			}
		}
		// The engagement's setting caps what leaves Synapse as it stands now, not as it stood when
		// the job was queued: none sends nothing, signal sends only the event label and link.
		// Personal messages otherwise go at summary, the most an inbox row holds.
		override, err := engagementOverride(ctx, tx, tenant, engagement)
		if err != nil {
			return err
		}
		class, deliver := notification.EffectiveDataClass(notification.DataClassSummary, override)
		if !deliver {
			return nil
		}
		out.Title, out.Summary = notification.PersonalTextAt(out.EventType, out.Title, out.Summary, class)
		scanErr = tx.QueryRow(ctx, `SELECT value FROM user_contacts WHERE tenant_id=$1 AND user_id=$2 AND id=$3 AND version=$4 AND kind=$5 AND verified_at IS NOT NULL`, tenant, user, contact, version, channel).Scan(&out.Recipient)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		ok = true
		return nil
	})
	if err != nil || !ok {
		return ports.PersonalMessage{}, false, err
	}
	return out, true, nil
}

// ListPersonalDefaults returns the tenant's stored defaults (#1418).
func (s *InboxStore) ListPersonalDefaults(ctx context.Context, tenant shared.ID) ([]notification.PersonalDefault, error) {
	var out []notification.PersonalDefault
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT event_type, channel, enabled, revision FROM notification_personal_defaults WHERE tenant_id=$1 ORDER BY event_type, channel`, tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item notification.PersonalDefault
			var event string
			if err := rows.Scan(&event, &item.Channel, &item.Enabled, &item.Revision); err != nil {
				return err
			}
			item.EventType = notification.EventType(event)
			out = append(out, item)
		}
		return rows.Err()
	})
	return out, err
}

// SavePersonalDefault stores one tenant default and its audit entry in one transaction.
func (s *InboxStore) SavePersonalDefault(ctx context.Context, tenant shared.ID, actor string, event notification.EventType, channel string, enabled bool, revision int, at time.Time) (notification.PersonalDefault, error) {
	out := notification.PersonalDefault{EventType: event, Channel: channel, Enabled: enabled}
	err := WithTenant(ctx, s.pool, tenant.String(), func(tx pgx.Tx) error {
		var err error
		if revision < 1 {
			err = tx.QueryRow(ctx, `INSERT INTO notification_personal_defaults(tenant_id,event_type,channel,enabled,revision,updated_at,updated_by) VALUES($1,$2,$3,$4,1,$5,$6) ON CONFLICT DO NOTHING RETURNING revision`, tenant, event, channel, enabled, at, actor).Scan(&out.Revision)
		} else {
			err = tx.QueryRow(ctx, `UPDATE notification_personal_defaults SET enabled=$4, revision=revision+1, updated_at=$5, updated_by=$6 WHERE tenant_id=$1 AND event_type=$2 AND channel=$3 AND revision=$7 RETURNING revision`, tenant, event, channel, enabled, at, actor, revision).Scan(&out.Revision)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: personal default revision is stale", shared.ErrConflict)
		}
		if err != nil {
			return err
		}
		return appendTenantAudit(ctx, tx, tenant.String(), ports.AuditEntry{Actor: actor, Action: "notification.personal_default.updated", Target: string(event) + ":" + channel, At: at,
			Metadata: map[string]string{"event_type": string(event), "channel": channel, "enabled": strconv.FormatBool(enabled)}})
	})
	return out, err
}

// A queued recipient may have several captured relations. At least one still
// valid relation is enough; losing review permission does not revoke a separately
// selected engagement lead, while a former administrator loses the mandatory role.
func personalRecipientAuthorized(event notification.EventType, roles []string, userRole string) bool {
	switch event {
	case notification.EventApprovalRequested, notification.EventApprovalDecided, notification.EventApprovalTimedOut, notification.EventEvidenceChainBroken:
		for _, role := range roles {
			if notification.PersonalRoleSupported(event, role) != nil {
				continue
			}
			switch role {
			case notification.RoleApprover:
				if userRole == "admin" || userRole == "reviewer" {
					return true
				}
			case notification.RoleTenantAdmin:
				if userRole == "admin" {
					return true
				}
			default:
				return true
			}
		}
		return false
	default:
		return true
	}
}
