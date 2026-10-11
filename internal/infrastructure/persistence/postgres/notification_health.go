package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Channel health persistence (#1464, migration 0196). The counting rules live in the domain
// (notification.ChannelHealth.Observe); this file locks the channel row, applies them and, on the
// transition to paused, performs the side effects in the same transaction.

const pausedDeliveryReason = "channel_paused"

func (r *NotificationRepository) RecordChannelOutcome(ctx context.Context, tenant shared.ID, o ports.NotificationChannelOutcome) (ports.NotificationChannelTransition, error) {
	var out ports.NotificationChannelTransition
	if o.Class == notification.AttemptIgnored {
		return out, nil
	}
	if tenant.IsZero() || o.ChannelID.IsZero() || o.At.IsZero() {
		return out, fmt.Errorf("%w: channel outcome requires tenant, channel and time", shared.ErrValidation)
	}
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		if o.Class == notification.AttemptDelivered {
			// The common case is a healthy channel, so a success writes only when there is a count
			// to clear. A paused channel keeps its count until an administrator resumes it.
			_, err := tx.Exec(ctx, `UPDATE notification_channels SET consecutive_permanent_failures=0
				WHERE tenant_id=$1 AND id=$2 AND consecutive_permanent_failures>0 AND paused_at IS NULL AND deleted_at IS NULL`, tenant, o.ChannelID)
			return err
		}
		if o.DeliveryID.IsZero() || o.AttemptID.IsZero() {
			return fmt.Errorf("%w: a counted failure must name its delivery and attempt", shared.ErrValidation)
		}
		var name, typ string
		var health notification.ChannelHealth
		err := tx.QueryRow(ctx, `SELECT name,channel_type,`+channelHealthColumns+` FROM notification_channels
			WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`, tenant, o.ChannelID).
			Scan(&name, &typ, &health.ConsecutiveFailures, &health.LastFailureCode, &health.LastFailureAt, &health.PausedAt, &health.PausedReason)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // deleted meanwhile: there is no health left to keep
		}
		if err != nil {
			return err
		}
		health.State = healthState(health.PausedAt)
		next, effect := health.Observe(o.Class, o.Code, o.At, o.Threshold)
		out.Health = next
		if effect == notification.HealthUnchanged {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE notification_channels SET consecutive_permanent_failures=$3,last_failure_code=$4,last_failure_at=$5,paused_at=$6,paused_reason=NULLIF($7,'')
			WHERE tenant_id=$1 AND id=$2`, tenant, o.ChannelID, next.ConsecutiveFailures, next.LastFailureCode, next.LastFailureAt, next.PausedAt, next.PausedReason); err != nil {
			return err
		}
		if effect != notification.HealthPausedNow {
			return nil
		}
		pauseID := stableID(tenant.String(), o.ChannelID.String(), "pause", o.AttemptID.String())
		if _, err := tx.Exec(ctx, `INSERT INTO notification_channel_health_events(tenant_id,id,channel_id,action,reason,failure_code,failures,delivery_id,attempt_id,actor,occurred_at)
			VALUES($1,$2,$3,'paused',$4,$5,$6,$7,$8,'system',$9) ON CONFLICT DO NOTHING`,
			tenant, pauseID, o.ChannelID, next.PausedReason, next.LastFailureCode, next.ConsecutiveFailures, o.DeliveryID, o.AttemptID, next.PausedAt); err != nil {
			return fmt.Errorf("record channel pause: %w", err)
		}
		// Queued work is cancelled rather than held: releasing a backlog of stale alerts on resume
		// would be worse than dropping them, and this mirrors disabling a channel. An attempt that
		// is already in flight finishes; its outcome no longer changes the paused health.
		if _, err := tx.Exec(ctx, `WITH changed AS (
				UPDATE notification_deliveries d SET state='cancelled',last_error=$3,next_attempt_at=NULL,updated_at=$4
				WHERE tenant_id=$1 AND channel_id=$2 AND state IN ('pending','retrying')
				AND NOT EXISTS(SELECT 1 FROM notification_delivery_attempts a WHERE a.tenant_id=d.tenant_id AND a.delivery_id=d.id AND a.outcome='started')
				RETURNING id)
			INSERT INTO notification_audit_intents(tenant_id,id,delivery_id,action,error_code,occurred_at)
			SELECT $1,'cancel:'||id,id,'notification.delivery_cancelled',$3,$4 FROM changed ON CONFLICT DO NOTHING`,
			tenant, o.ChannelID, pausedDeliveryReason, next.PausedAt); err != nil {
			return fmt.Errorf("cancel paused channel deliveries: %w", err)
		}
		event, err := notification.NewChannelPausedEvent(tenant, o.ChannelID, notification.ChannelType(typ), name, next, pauseID)
		if err != nil {
			return err
		}
		event.ID = stableID(tenant.String(), event.SourceKind, event.SourceID)
		if _, err := r.publishTx(ctx, tx, event, ""); err != nil {
			return fmt.Errorf("publish channel pause notice: %w", err)
		}
		out.Paused, out.PauseID = true, pauseID
		return nil
	})
	if err != nil {
		return ports.NotificationChannelTransition{}, err
	}
	return out, nil
}

func (r *NotificationRepository) ResumeChannel(ctx context.Context, tenant, id shared.ID, revision int, actor string, at time.Time) (notification.Channel, error) {
	actor = strings.TrimSpace(actor)
	if tenant.IsZero() || id.IsZero() || revision < 1 || actor == "" || len(actor) > 200 || at.IsZero() {
		return notification.Channel{}, fmt.Errorf("%w: resume requires a channel, revision and actor", shared.ErrValidation)
	}
	var out notification.Channel
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		if err := scanChannel(tx.QueryRow(ctx, channelSelect+` WHERE tenant_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`, tenant, id), &out); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("notification channel %s: %w", id, shared.ErrNotFound)
			}
			return err
		}
		if out.Revision != revision {
			return fmt.Errorf("notification channel revision is stale: %w", shared.ErrConflict)
		}
		previous := out.Health
		next, err := previous.Resume()
		if err != nil {
			return err
		}
		at = at.UTC()
		if _, err := tx.Exec(ctx, `UPDATE notification_channels SET paused_at=NULL,paused_reason=NULL,consecutive_permanent_failures=0,revision=revision+1,updated_at=$3
			WHERE tenant_id=$1 AND id=$2 AND revision=$4`, tenant, id, at, revision); err != nil {
			return err
		}
		resumeID := stableID(tenant.String(), id.String(), "resume", strconv.Itoa(revision))
		if _, err := tx.Exec(ctx, `INSERT INTO notification_channel_health_events(tenant_id,id,channel_id,action,reason,failure_code,failures,actor,occurred_at)
			VALUES($1,$2,$3,'resumed',$4,$5,$6,$7,$8)`, tenant, resumeID, id, previous.PausedReason, previous.LastFailureCode, previous.ConsecutiveFailures, actor, at); err != nil {
			return fmt.Errorf("record channel resume: %w", err)
		}
		out.Health, out.Revision, out.UpdatedAt = next, revision+1, at
		return nil
	})
	return out, err
}

func (r *NotificationRepository) ListChannelHealthEvents(ctx context.Context, tenant, channel shared.ID, limit int) ([]notification.ChannelHealthEvent, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	if _, err := r.GetChannel(ctx, tenant, channel); err != nil {
		return nil, err
	}
	out := []notification.ChannelHealthEvent{}
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id,channel_id,action,reason,failure_code,failures,COALESCE(delivery_id,''),COALESCE(attempt_id,''),actor,occurred_at
			FROM notification_channel_health_events WHERE tenant_id=$1 AND channel_id=$2
			ORDER BY occurred_at DESC,id DESC LIMIT $3`, tenant, channel, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e notification.ChannelHealthEvent
			if err := rows.Scan(&e.ID, &e.ChannelID, &e.Action, &e.Reason, &e.FailureCode, &e.Failures, &e.DeliveryID, &e.AttemptID, &e.Actor, &e.OccurredAt); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}
