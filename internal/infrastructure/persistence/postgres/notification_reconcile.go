package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

func notificationAdmission(ctx context.Context, tx pgx.Tx, tenant shared.ID, kind string, maximum int) error {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,78146))", tenant.String()+":"+kind); err != nil {
		return err
	}
	var count int
	query := ""
	switch kind {
	case "channel":
		query = "SELECT count(*) FROM notification_channels WHERE tenant_id=$1 AND deleted_at IS NULL"
	case "rule":
		query = "SELECT count(*) FROM notification_rules WHERE tenant_id=$1"
	case "delivery":
		query = "SELECT count(*) FROM notification_deliveries WHERE tenant_id=$1 AND state IN ('pending','retrying')"
	default:
		return shared.ErrValidation
	}
	if err := tx.QueryRow(ctx, query, tenant).Scan(&count); err != nil {
		return err
	}
	if count >= maximum {
		return fmt.Errorf("%w: notification %s capacity reached", shared.ErrSaturated, kind)
	}
	return nil
}

func (r *NotificationRepository) reconcileTx(ctx context.Context, tx pgx.Tx, tenant shared.ID) error {
	// Repair the crash window between queue.Deadletter and OnDeadLetter. Lock the
	// failed job before its delivery, matching redrive and the callback. A query
	// that only joins job state could observe a pre-redrive snapshot and incorrectly
	// dead-letter the newly queued cycle.
	rows, err := tx.Query(ctx, `SELECT j.id,d.id,j.claim_fence
		FROM jobs j JOIN notification_deliveries d
		  ON d.tenant_id=j.tenant_id AND j.id='notification-'||d.id
		WHERE j.tenant_id=$1 AND j.kind='notification.deliver' AND j.status='failed'
		  AND d.state IN ('pending','retrying')
		ORDER BY j.updated_at,d.id LIMIT 200 FOR UPDATE OF j SKIP LOCKED`, tenant)
	if err != nil {
		return err
	}
	type deadCandidate struct {
		jobID, deliveryID string
		fence             int64
	}
	var candidates []deadCandidate
	for rows.Next() {
		var candidate deadCandidate
		if err := rows.Scan(&candidate.jobID, &candidate.deliveryID, &candidate.fence); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, candidate := range candidates {
		tag, err := tx.Exec(ctx, `UPDATE notification_deliveries SET state='dead_letter',last_error='worker_dead_letter',next_attempt_at=NULL,updated_at=now()
			WHERE tenant_id=$1 AND id=$2 AND state IN ('pending','retrying')`, tenant, candidate.deliveryID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO notification_audit_intents(tenant_id,id,delivery_id,action,error_code,occurred_at)
			VALUES($1,$2,$3,'notification.delivery_failed','worker_dead_letter',now()) ON CONFLICT DO NOTHING`,
			tenant, fmt.Sprintf("dead:%s:%d", candidate.deliveryID, candidate.fence), candidate.deliveryID); err != nil {
			return err
		}
	}
	rows, err = tx.Query(ctx, `SELECT id,delivery_id,action,error_code,occurred_at FROM notification_audit_intents WHERE tenant_id=$1 AND recorded_at IS NULL ORDER BY occurred_at,id LIMIT 200 FOR UPDATE SKIP LOCKED`, tenant)
	if err != nil {
		return err
	}
	type intent struct {
		id, delivery, action, code string
		at                         time.Time
	}
	var intents []intent
	for rows.Next() {
		var v intent
		if err := rows.Scan(&v.id, &v.delivery, &v.action, &v.code, &v.at); err != nil {
			rows.Close()
			return err
		}
		intents = append(intents, v)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	// Keep audit failure isolated from source projection and terminal repair.
	for _, v := range intents {
		auditCtx := shared.WithTenant(context.WithValue(ctx, tenantTransactionKey{}, tenantTransaction{tenantID: tenant.String(), tx: tx}), tenant)
		err := NewAuditLog(r.pool).RecordOnce(auditCtx, ports.AuditEntry{Actor: "synapse-worker", Action: v.action, Target: v.delivery, At: v.at, Metadata: map[string]string{"idempotency_key": "notification:" + v.id, "error_code": v.code}})
		if err != nil {
			break
		}
		if _, err := tx.Exec(ctx, `UPDATE notification_audit_intents SET recorded_at=now() WHERE tenant_id=$1 AND id=$2`, tenant, v.id); err != nil {
			return err
		}
	}
	return nil
}
