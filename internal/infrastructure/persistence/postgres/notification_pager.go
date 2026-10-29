package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

var _ ports.NotificationPagerRepository = (*NotificationRepository)(nil)

type pagerEpisode struct {
	tenant        shared.ID
	kind, subject string
	episode       int64
	terminal      string
}

// lockPagerEpisode serializes source publication and receipt admission for one occurrence.
func lockPagerEpisode(ctx context.Context, tx pgx.Tx, e notification.Event) (pagerEpisode, error) {
	p := pagerEpisode{tenant: e.TenantID, kind: e.SubjectKind, subject: e.SubjectID, episode: e.PagerLifecycle.Episode}
	_, err := tx.Exec(ctx, `INSERT INTO notification_pager_episodes(tenant_id,subject_kind,subject_id,episode) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, p.tenant, p.kind, p.subject, p.episode)
	if err != nil {
		return p, err
	}
	err = tx.QueryRow(ctx, `SELECT COALESCE(terminal_event_id,'') FROM notification_pager_episodes WHERE tenant_id=$1 AND subject_kind=$2 AND subject_id=$3 AND episode=$4 FOR UPDATE`, p.tenant, p.kind, p.subject, p.episode).Scan(&p.terminal)
	if err != nil {
		return p, err
	}
	if e.PagerLifecycle.Terminal && p.terminal == "" {
		p.terminal = e.ID.String()
		_, err = tx.Exec(ctx, `UPDATE notification_pager_episodes SET terminal_event_id=$5 WHERE tenant_id=$1 AND subject_kind=$2 AND subject_id=$3 AND episode=$4`, p.tenant, p.kind, p.subject, p.episode, p.terminal)
	}
	return p, err
}

// schedulePagerCloses derives close obligations exclusively from acknowledged triggers.
func schedulePagerCloses(ctx context.Context, tx pgx.Tx, p pagerEpisode) ([]shared.ID, error) {
	if p.terminal == "" {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT o.channel_id,MIN(o.channel_version) FROM notification_pager_operations o WHERE o.tenant_id=$1 AND o.subject_kind=$2 AND o.subject_id=$3 AND o.episode=$4 AND NOT o.is_close AND o.state='done' AND NOT EXISTS(SELECT 1 FROM notification_pager_operations inflight WHERE inflight.tenant_id=o.tenant_id AND inflight.subject_kind=o.subject_kind AND inflight.subject_id=o.subject_id AND inflight.episode=o.episode AND inflight.channel_id=o.channel_id AND inflight.state IN ('sending','confirming','unknown')) GROUP BY o.channel_id ORDER BY o.channel_id`, p.tenant, p.kind, p.subject, p.episode)
	if err != nil {
		return nil, err
	}
	type target struct {
		id      shared.ID
		version int
	}
	var targets []target
	for rows.Next() {
		var t target
		if err = rows.Scan(&t.id, &t.version); err != nil {
			rows.Close()
			return nil, err
		}
		targets = append(targets, t)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	var ids []shared.ID
	for _, t := range targets {
		did := stableID(p.tenant.String(), p.terminal, t.id.String(), "")
		at := time.Now().UTC()
		tag, err := tx.Exec(ctx, `INSERT INTO notification_deliveries(tenant_id,id,event_id,channel_id,channel_version,channel_type,recipient,matched_rules,state,created_at,updated_at) SELECT $1,$2,$3,$4,$5,channel_type,'','[]'::jsonb,'pending',$6,$6 FROM notification_channels WHERE tenant_id=$1 AND id=$4 ON CONFLICT(tenant_id,event_id,channel_id,recipient) DO NOTHING`, p.tenant, did, p.terminal, t.id, t.version, at)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() == 0 {
			continue
		}
		_, err = tx.Exec(ctx, `INSERT INTO notification_pager_operations(tenant_id,delivery_id,subject_kind,subject_id,episode,channel_id,channel_version,is_close,state) VALUES($1,$2,$3,$4,$5,$6,$7,true,'pending') ON CONFLICT DO NOTHING`, p.tenant, did, p.kind, p.subject, p.episode, t.id, t.version)
		if err != nil {
			return nil, err
		}
		payload, _ := json.Marshal(map[string]string{"delivery_id": did.String()})
		_, err = tx.Exec(ctx, `INSERT INTO jobs(id,tenant_id,kind,payload,status,available_at) VALUES($1,$2,'notification.deliver',$3,'queued',$4) ON CONFLICT(id) DO NOTHING`, "notification-"+did.String(), p.tenant, payload, at)
		if err != nil {
			return nil, err
		}
		ids = append(ids, did)
	}
	return ids, nil
}

func pagerForDelivery(ctx context.Context, tx pgx.Tx, tenant, delivery shared.ID) (pagerEpisode, error) {
	p := pagerEpisode{tenant: tenant}
	err := tx.QueryRow(ctx, `SELECT subject_kind,subject_id,episode FROM notification_pager_operations WHERE tenant_id=$1 AND delivery_id=$2`, tenant, delivery).Scan(&p.kind, &p.subject, &p.episode)
	return p, err
}
func lockStoredPagerEpisode(ctx context.Context, tx pgx.Tx, p *pagerEpisode) error {
	return tx.QueryRow(ctx, `SELECT COALESCE(terminal_event_id,'') FROM notification_pager_episodes WHERE tenant_id=$1 AND subject_kind=$2 AND subject_id=$3 AND episode=$4 FOR UPDATE`, p.tenant, p.kind, p.subject, p.episode).Scan(&p.terminal)
}

func (r *NotificationRepository) AdmitPagerMutation(ctx context.Context, tenant, delivery shared.ID, jobID string, fence int64, operation shared.ID) (out ports.PagerMutation, err error) {
	if operation.IsZero() || jobID != "notification-"+delivery.String() {
		return out, fmt.Errorf("%w: invalid pager operation", shared.ErrValidation)
	}
	err = WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		var ok int
		if e := tx.QueryRow(ctx, `SELECT 1 FROM jobs WHERE tenant_id=$1 AND id=$2 AND kind='notification.deliver' AND status='claimed' AND claim_fence=$3 AND claimed_until>now() FOR UPDATE`, tenant, jobID, fence).Scan(&ok); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return ports.ErrStaleLease
			}
			return e
		}
		if e := tx.QueryRow(ctx, `SELECT 1 FROM notification_delivery_attempts WHERE tenant_id=$1 AND delivery_id=$2 AND id=$3 AND outcome='started'`, tenant, delivery, operation).Scan(&ok); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return fmt.Errorf("%w: pager attempt missing", shared.ErrConflict)
			}
			return e
		}
		p, e := pagerForDelivery(ctx, tx, tenant, delivery)
		if e != nil {
			return e
		}
		var enabled bool
		var current int
		if e = tx.QueryRow(ctx, `SELECT c.enabled AND c.deleted_at IS NULL AND c.paused_at IS NULL,c.secret_version FROM notification_channels c JOIN notification_pager_operations o ON o.tenant_id=c.tenant_id AND o.channel_id=c.id WHERE o.tenant_id=$1 AND o.delivery_id=$2 FOR UPDATE OF c`, tenant, delivery).Scan(&enabled, &current); e != nil {
			return e
		}
		if e = lockStoredPagerEpisode(ctx, tx, &p); e != nil {
			return e
		}
		var state, opID, request, remote, channelID string
		var version int
		var close bool
		e = tx.QueryRow(ctx, `SELECT state,operation_id,provider_request_ref,remote_ref,channel_id,channel_version,is_close FROM notification_pager_operations WHERE tenant_id=$1 AND delivery_id=$2 FOR UPDATE`, tenant, delivery).Scan(&state, &opID, &request, &remote, &channelID, &version, &close)
		if e != nil {
			return e
		}
		out.OperationID = shared.ID(opID)
		out.ProviderRequestRef = request
		out.RemoteRef = remote
		switch state {
		case "done":
			out.Action = "complete"
			return nil
		case "suppressed":
			out.Action = "suppressed"
			return nil
		case "unknown", "sending", "failed":
			out.Action = "blocked"
			out.Code = "pager_" + state
			return nil
		}
		if state == "pending" && !close && p.terminal != "" {
			_, e = tx.Exec(ctx, `UPDATE notification_pager_operations SET state='suppressed',blocked_reason='episode_terminal' WHERE tenant_id=$1 AND delivery_id=$2`, tenant, delivery)
			out.Action = "suppressed"
			return e
		}
		if !enabled || current != version {
			out.Action = "blocked"
			out.Code = "pager_channel_unavailable"
			_, e = tx.Exec(ctx, `UPDATE notification_pager_operations SET blocked_reason=$3 WHERE tenant_id=$1 AND delivery_id=$2`, tenant, delivery, out.Code)
			return e
		}
		if state == "confirming" {
			out.Action = "poll"
			return nil
		}
		var laneBusy bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_pager_operations WHERE tenant_id=$1 AND subject_kind=$2 AND subject_id=$3 AND episode=$4 AND channel_id=$5 AND delivery_id<>$6 AND state IN ('sending','confirming','unknown'))`, tenant, p.kind, p.subject, p.episode, channelID, delivery).Scan(&laneBusy); e != nil {
			return e
		}
		if laneBusy {
			out.Action = "blocked"
			out.Code = "pager_waiting"
			return nil
		}
		if !close {
			var predecessor bool
			e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_pager_operations o JOIN notification_deliveries d ON d.tenant_id=o.tenant_id AND d.id=o.delivery_id JOIN notification_deliveries current_d ON current_d.tenant_id=$1 AND current_d.id=$6 WHERE o.tenant_id=$1 AND o.subject_kind=$2 AND o.subject_id=$3 AND o.episode=$4 AND o.channel_id=$5 AND NOT o.is_close AND o.state='pending' AND d.state<>'cancelled' AND (d.created_at,d.id)<(current_d.created_at,current_d.id))`, tenant, p.kind, p.subject, p.episode, channelID, delivery).Scan(&predecessor)
			if e != nil {
				return e
			}
			if predecessor {
				out.Action = "blocked"
				out.Code = "pager_waiting"
				return nil
			}
		}
		if close {
			e = tx.QueryRow(ctx, `SELECT remote_ref FROM notification_pager_operations WHERE tenant_id=$1 AND subject_kind=$2 AND subject_id=$3 AND episode=$4 AND channel_id=$5 AND NOT is_close AND state='done' ORDER BY delivery_id LIMIT 1`, tenant, p.kind, p.subject, p.episode, channelID).Scan(&out.SubjectAnchor)
			if e != nil {
				return e
			}
			if out.SubjectAnchor == "" {
				out.Action = "blocked"
				out.Code = "pager_missing_anchor"
				return nil
			}
		}
		_, e = tx.Exec(ctx, `UPDATE notification_pager_operations SET state='sending',operation_id=$3,blocked_reason='' WHERE tenant_id=$1 AND delivery_id=$2 AND state='pending'`, tenant, delivery, operation)
		if e != nil {
			return e
		}
		out.Action = "send"
		out.OperationID = operation
		return nil
	})
	return out, err
}

func (r *NotificationRepository) RecordPagerReceipt(ctx context.Context, tenant, delivery, operation shared.ID, result ports.NotificationSendResult) error {
	if operation.IsZero() || len(result.ProviderRequestRef) > 512 || len(result.RemoteRef) > 512 {
		return fmt.Errorf("%w: invalid pager receipt", shared.ErrValidation)
	}
	resume := false
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		p, e := pagerForDelivery(ctx, tx, tenant, delivery)
		if e != nil {
			return e
		}
		if e = lockStoredPagerEpisode(ctx, tx, &p); e != nil {
			return e
		}
		var state, opID, request, remote string
		var close bool
		e = tx.QueryRow(ctx, `SELECT state,operation_id,provider_request_ref,remote_ref,is_close FROM notification_pager_operations WHERE tenant_id=$1 AND delivery_id=$2 FOR UPDATE`, tenant, delivery).Scan(&state, &opID, &request, &remote, &close)
		if e != nil {
			return e
		}
		if opID != operation.String() {
			return fmt.Errorf("%w: pager operation mismatch", shared.ErrConflict)
		}
		if state == "done" || state == "failed" || state == "suppressed" {
			return nil
		}
		next := state
		switch {
		case result.RemoteRef != "" && result.ErrorCode == "" && result.StatusCode >= 200 && result.StatusCode < 300:
			next = "done"
			remote = result.RemoteRef
		case result.ErrorCode == "jsm_request_failed":
			next = "failed"
		case result.ProviderRequestRef != "":
			if request != "" && request != result.ProviderRequestRef {
				return fmt.Errorf("%w: pager request mismatch", shared.ErrConflict)
			}
			request = result.ProviderRequestRef
			next = "confirming"
		case state == "confirming": // Poll failures never authorize a second mutation.
		case result.StatusCode == 429:
			next = "pending"
			opID = ""
		case result.StatusCode >= 400 && result.StatusCode < 500:
			next = "failed"
		case result.ErrorCode == "channel_config_invalid" || result.ErrorCode == "format_failed" || result.ErrorCode == "pager_key_unavailable" || result.ErrorCode == "pager_resolve_unpaired" || result.ErrorCode == "request_invalid":
			if result.Retryable {
				next = "pending"
				opID = ""
			} else {
				next = "failed"
			}
		default:
			next = "unknown"
		}
		_, e = tx.Exec(ctx, `UPDATE notification_pager_operations SET state=$3,provider_request_ref=$4,remote_ref=$5,operation_id=$6 WHERE tenant_id=$1 AND delivery_id=$2`, tenant, delivery, next, request, remote, opID)
		if e != nil {
			return e
		}
		resume = (next == "confirming" || next == "done") && state != next
		if (next == "done" || next == "failed") && !close && p.terminal != "" {
			_, e = schedulePagerCloses(ctx, tx, p)
		}
		return e
	})
	if err != nil || !resume {
		return err
	}
	return r.wakeKnownPagerRequest(ctx, tenant, delivery, operation)
}

// The callback commits its receipt before acquiring any queue lock. Only a
// failed job is revived; an active claimant or operator cancellation wins.
func (r *NotificationRepository) wakeKnownPagerRequest(ctx context.Context, tenant, delivery, operation shared.ID) error {
	return WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM jobs WHERE tenant_id=$1 AND id=$2 AND kind='notification.deliver' FOR UPDATE`, tenant, "notification-"+delivery.String()).Scan(&status); err != nil {
			return err
		}
		if status != "failed" && status != "done" {
			return nil
		}
		_, err := wakeKnownPagerRequestTx(ctx, tx, tenant, delivery, operation)
		return err
	})
}

// Caller holds the failed job row, before locking the episode and operation.
func wakeKnownPagerRequestTx(ctx context.Context, tx pgx.Tx, tenant, delivery, operation shared.ID) (bool, error) {
	p, err := pagerForDelivery(ctx, tx, tenant, delivery)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err = lockStoredPagerEpisode(ctx, tx, &p); err != nil {
		return false, err
	}
	var state, opID string
	if err = tx.QueryRow(ctx, `SELECT state,operation_id FROM notification_pager_operations WHERE tenant_id=$1 AND delivery_id=$2 FOR UPDATE`, tenant, delivery).Scan(&state, &opID); err != nil {
		return false, err
	}
	if (state != "confirming" && state != "done") || (!operation.IsZero() && opID != operation.String()) {
		return false, nil
	}
	var jobStatus string
	if err = tx.QueryRow(ctx, `SELECT status FROM jobs WHERE tenant_id=$1 AND id=$2`, tenant, "notification-"+delivery.String()).Scan(&jobStatus); err != nil {
		return false, err
	}
	if jobStatus != "failed" && jobStatus != "done" {
		return false, nil
	}
	tag, err := tx.Exec(ctx, `UPDATE notification_deliveries d SET state='pending',last_error='',next_attempt_at=NULL,updated_at=now() FROM notification_channels c WHERE d.tenant_id=$1 AND d.id=$2 AND (d.state IN ('pending','retrying','dead_letter') OR (d.state='cancelled' AND ($4 OR $5))) AND c.tenant_id=d.tenant_id AND c.id=d.channel_id AND ($4 OR (c.enabled AND c.deleted_at IS NULL AND c.paused_at IS NULL AND c.secret_version=d.channel_version AND ($3 OR d.last_error IN ('pager_sending','pager_unknown') OR ($5 AND d.state='cancelled')) AND NOT EXISTS (SELECT 1 FROM notification_events e JOIN notification_engagement_settings s ON s.tenant_id=e.tenant_id AND s.engagement_id=e.engagement_id WHERE e.tenant_id=d.tenant_id AND e.id=d.event_id AND s.external_notifications='none'))) AND (NOT $5 OR d.state='cancelled')`, tenant, delivery, !operation.IsZero(), state == "done", jobStatus == "done")
	if err != nil || tag.RowsAffected() == 0 {
		return false, err
	}
	tag, err = tx.Exec(ctx, `UPDATE jobs SET status='queued',attempts=0,claim_fence=claim_fence+1,claimed_until=NULL,available_at=now(),updated_at=now() WHERE tenant_id=$1 AND id=$2 AND status IN ('failed','done')`, tenant, "notification-"+delivery.String())
	return tag.RowsAffected() == 1, err
}

// ReconcilePagerAcknowledgement records an already accepted provider mutation without I/O.
func (r *NotificationRepository) ReconcilePagerAcknowledgement(ctx context.Context, tenant, delivery shared.ID, jobID string, fence int64) (bool, error) {
	if jobID != "notification-"+delivery.String() {
		return false, fmt.Errorf("%w: invalid pager job", shared.ErrValidation)
	}
	reconciled := false
	err := WithTenant(ctx, r.pool, tenant.String(), func(tx pgx.Tx) error {
		var ok int
		if e := tx.QueryRow(ctx, `SELECT 1 FROM jobs WHERE tenant_id=$1 AND id=$2 AND kind='notification.deliver' AND status='claimed' AND claim_fence=$3 AND claimed_until>now() FOR UPDATE`, tenant, jobID, fence).Scan(&ok); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return ports.ErrStaleLease
			}
			return e
		}
		p, e := pagerForDelivery(ctx, tx, tenant, delivery)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		if e = lockStoredPagerEpisode(ctx, tx, &p); e != nil {
			return e
		}
		var state, opID, remote string
		if e = tx.QueryRow(ctx, `SELECT state,operation_id,remote_ref FROM notification_pager_operations WHERE tenant_id=$1 AND delivery_id=$2 FOR UPDATE`, tenant, delivery).Scan(&state, &opID, &remote); e != nil {
			return e
		}
		if state != "done" || remote == "" {
			return nil
		}
		if _, e = tx.Exec(ctx, `UPDATE notification_delivery_attempts SET finished_at=now(),outcome='delivered',response_code=0,error_code='' WHERE tenant_id=$1 AND delivery_id=$2 AND id=$3 AND outcome='started'`, tenant, delivery, opID); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE notification_deliveries SET state='delivered',last_error='',next_attempt_at=NULL,delivered_at=COALESCE(delivered_at,now()),remote_ref=$3,provider_request_ref='',updated_at=now() WHERE tenant_id=$1 AND id=$2 AND state IN ('pending','retrying','dead_letter','cancelled','delivered')`, tenant, delivery, remote); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO notification_audit_intents(tenant_id,id,delivery_id,action,error_code,occurred_at) VALUES($1,$2,$3,'notification.delivery_delivered','',now()) ON CONFLICT DO NOTHING`, tenant, "pager-ack:"+delivery.String(), delivery); e != nil {
			return e
		}
		reconciled = true
		return nil
	})
	return reconciled, err
}

func wakePagerLaneHeadTx(ctx context.Context, tx pgx.Tx, tenant, delivery shared.ID) error {
	p, err := pagerForDelivery(ctx, tx, tenant, delivery)
	if err != nil {
		return err
	}
	if err = lockStoredPagerEpisode(ctx, tx, &p); err != nil {
		return err
	}
	var channel, state string
	if err = tx.QueryRow(ctx, `SELECT channel_id,state FROM notification_pager_operations WHERE tenant_id=$1 AND delivery_id=$2 FOR UPDATE`, tenant, delivery).Scan(&channel, &state); err != nil {
		return err
	}
	if state != "pending" {
		return nil
	}
	var waiting bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_pager_operations o JOIN notification_deliveries d ON d.tenant_id=o.tenant_id AND d.id=o.delivery_id JOIN notification_deliveries current_d ON current_d.tenant_id=$1 AND current_d.id=$6 WHERE o.tenant_id=$1 AND o.subject_kind=$2 AND o.subject_id=$3 AND o.episode=$4 AND o.channel_id=$5 AND o.delivery_id<>$6 AND (o.state IN ('sending','confirming','unknown') OR (o.state='pending' AND d.state<>'cancelled' AND (d.created_at,d.id)<(current_d.created_at,current_d.id))))`, tenant, p.kind, p.subject, p.episode, channel, delivery).Scan(&waiting)
	if err != nil || waiting {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE notification_deliveries SET state='pending',last_error='',next_attempt_at=NULL,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND state='dead_letter' AND last_error='pager_waiting'`, tenant, delivery)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE jobs SET status='queued',attempts=0,claim_fence=claim_fence+1,claimed_until=NULL,available_at=now(),updated_at=now() WHERE tenant_id=$1 AND id=$2 AND status='failed'`, tenant, "notification-"+delivery.String())
	return err
}
