package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

func TestPagerRecoveryCancelledPendingPredecessor(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	tenant := shared.ID("pager-cancel-recovery")
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,'Pager recovery')`, tenant); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	txDo := func(f func(pgx.Tx) error) {
		t.Helper()
		if err := WithTenant(ctx, pool, tenant.String(), f); err != nil {
			t.Fatal(err)
		}
	}
	txDo(func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO notification_channels(tenant_id,id,name,channel_type,enabled,destination,recipients,revision,secret_version,created_at,updated_at) VALUES($1,'pager','Pager','jsm',true,'','[]',1,1,$2,$2)`, tenant, now); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO notification_channel_versions(tenant_id,channel_id,version,sealed_config,created_at) VALUES($1,'pager',1,'sealed',$2)`, tenant, now)
		return err
	})
	publish := func(id, subject string, rev int64) shared.ID {
		t.Helper()
		d, err := repo.PublishToChannel(ctx, notification.Event{TenantID: tenant, ID: shared.ID(id), Type: notification.EventFindingStatusChanged, SourceKind: "finding_status", SourceID: id, SchemaVersion: 1, OccurredAt: now, Data: json.RawMessage(`{}`), SubjectKind: "finding", SubjectID: subject, PagerLifecycle: notification.PagerLifecycle{Episode: 1, Revision: rev}}, "pager")
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	claim := func(d shared.ID, op string, fence int64, n int) {
		t.Helper()
		txDo(func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `UPDATE jobs SET status='claimed',claim_fence=$3,claimed_until=now()+interval '1 minute' WHERE tenant_id=$1 AND id=$2`, tenant, "notification-"+d.String(), fence); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT set_config('synapse.notification_pager_capability','pager-lifecycle-v1',true)`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO notification_delivery_attempts(tenant_id,id,delivery_id,attempt_number,started_at,outcome) VALUES($1,$2,$3,$4,now(),'started')`, tenant, op, d, n)
			return err
		})
	}
	admit := func(d shared.ID, op string, fence int64) string {
		t.Helper()
		a, err := repo.AdmitPagerMutation(ctx, tenant, d, "notification-"+d.String(), fence, shared.ID(op))
		if err != nil {
			t.Fatal(err)
		}
		if a.Action == "blocked" {
			return a.Code
		}
		return a.Action
	}
	// The first pending delivery was cancelled before a new update is published.
	first := publish("direct-first", "direct", 1)
	txDo(func(tx pgx.Tx) error {
		return cancelPendingDeliveries(ctx, tx, tenant, "pager", "channel_disabled", now)
	})
	second := publish("direct-second", "direct", 2)
	txDo(func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE notification_deliveries SET created_at=CASE WHEN id=$2 THEN $4::timestamptz ELSE $4::timestamptz+interval '1 second' END WHERE tenant_id=$1 AND id IN ($2,$3)`, tenant, first, second, now)
		return err
	})
	claim(second, "direct-op", 1, 1)
	if got := admit(second, "direct-op", 1); got != "send" {
		t.Fatalf("new update after cancellation: %s", got)
	}
	// A parked update is reconsidered after its unsent predecessor is cancelled.
	old := publish("waiting-first", "waiting", 1)
	next := publish("waiting-second", "waiting", 2)
	txDo(func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE notification_deliveries SET created_at=CASE WHEN id=$2 THEN $4::timestamptz ELSE $4::timestamptz+interval '1 second' END WHERE tenant_id=$1 AND id IN ($2,$3)`, tenant, old, next, now)
		return err
	})
	claim(next, "waiting-op", 1, 1)
	if got := admit(next, "waiting-op", 1); got != "pager_waiting" {
		t.Fatalf("expected predecessor to block: %s", got)
	}
	txDo(func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE notification_delivery_attempts SET outcome='failed' WHERE tenant_id=$1 AND id='waiting-op'`, tenant); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE jobs SET status='failed',claimed_until=NULL WHERE tenant_id=$1 AND id=$2`, tenant, "notification-"+next.String()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE notification_deliveries SET state='dead_letter',last_error='pager_waiting' WHERE tenant_id=$1 AND id=$2`, tenant, next); err != nil {
			return err
		}
		if err := cancelPendingDeliveries(ctx, tx, tenant, "pager", "channel_disabled", now); err != nil {
			return err
		}
		return repo.reconcileTx(ctx, tx, tenant)
	})
	txDo(func(tx pgx.Tx) error {
		var status, state string
		if err := tx.QueryRow(ctx, `SELECT j.status,d.state FROM jobs j JOIN notification_deliveries d ON j.tenant_id=d.tenant_id AND j.id='notification-'||d.id WHERE d.tenant_id=$1 AND d.id=$2`, tenant, next).Scan(&status, &state); err != nil {
			return err
		}
		if status != "queued" || state != "pending" {
			t.Fatalf("parked update not woken: %s %s", status, state)
		}
		return nil
	})
	claim(next, "waiting-retry", 2, 2)
	if got := admit(next, "waiting-retry", 2); got != "send" {
		t.Fatalf("woken update: %s", got)
	}
	// Cancellation cannot release an unresolved admitted mutation.
	busy := publish("busy-first", "busy", 1)
	claim(busy, "busy-op", 1, 1)
	if got := admit(busy, "busy-op", 1); got != "send" {
		t.Fatalf("busy first: %s", got)
	}
	later := publish("busy-second", "busy", 2)
	txDo(func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE notification_deliveries SET state='cancelled' WHERE tenant_id=$1 AND id=$2`, tenant, busy)
		return err
	})
	claim(later, "busy-later", 1, 1)
	if got := admit(later, "busy-later", 1); got != "pager_waiting" {
		t.Fatalf("unresolved cancelled mutation must block: %s", got)
	}
}

func TestPagerRecoveryDoneReceiptNotStarvedByDisabledConfirmations(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	tenant := shared.ID("pager-recovery-batch")
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,'Pager batch')`, tenant); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	txDo := func(f func(pgx.Tx) error) {
		t.Helper()
		if err := WithTenant(ctx, pool, tenant.String(), f); err != nil {
			t.Fatal(err)
		}
	}
	txDo(func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO notification_channels(tenant_id,id,name,channel_type,enabled,destination,recipients,revision,secret_version,created_at,updated_at) VALUES($1,'pager','Pager','jsm',true,'','[]',1,1,$2,$2)`, tenant, now); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO notification_channel_versions(tenant_id,channel_id,version,sealed_config,created_at) VALUES($1,'pager',1,'sealed',$2)`, tenant, now)
		return err
	})
	var done shared.ID
	for i := 0; i < 201; i++ {
		id := fmt.Sprintf("event-%03d", i)
		d, err := repo.PublishToChannel(ctx, notification.Event{TenantID: tenant, ID: shared.ID(id), Type: notification.EventFindingStatusChanged, SourceKind: "finding_status", SourceID: id, SchemaVersion: 1, OccurredAt: now, Data: json.RawMessage(`{}`), SubjectKind: "finding", SubjectID: id, PagerLifecycle: notification.PagerLifecycle{Episode: 1, Revision: 1}}, "pager")
		if err != nil {
			t.Fatal(err)
		}
		if i == 200 {
			done = d
		}
	}
	txDo(func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE notification_channels SET enabled=false WHERE tenant_id=$1 AND id='pager'`, tenant); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE notification_pager_operations SET state=CASE WHEN delivery_id=$2 THEN 'done' ELSE 'confirming' END,operation_id='accepted',provider_request_ref='request',remote_ref=CASE WHEN delivery_id=$2 THEN 'alias' ELSE '' END WHERE tenant_id=$1`, tenant, done); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE notification_deliveries SET state='dead_letter',last_error='pager_unknown' WHERE tenant_id=$1`, tenant); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE jobs SET status='failed',updated_at=CASE WHEN id=$2 THEN $3::timestamptz+interval '1 second' ELSE $3::timestamptz END WHERE tenant_id=$1`, tenant, "notification-"+done.String(), now); err != nil {
			return err
		}
		return repo.reconcileTx(ctx, tx, tenant)
	})
	txDo(func(tx pgx.Tx) error {
		var status string
		var untouched int
		if err := tx.QueryRow(ctx, `SELECT status FROM jobs WHERE tenant_id=$1 AND id=$2`, tenant, "notification-"+done.String()).Scan(&status); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_pager_operations o JOIN jobs j ON j.tenant_id=o.tenant_id AND j.id='notification-'||o.delivery_id WHERE o.tenant_id=$1 AND o.state='confirming' AND j.status='failed'`, tenant).Scan(&untouched); err != nil {
			return err
		}
		if status != "queued" || untouched != 200 {
			t.Fatalf("done=%s untouched confirmations=%d", status, untouched)
		}
		return nil
	})
}

func TestPagerRecoveryCancelledConfirmationResumesWhenEnabled(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	tenant := shared.ID("pager-resume-confirmation")
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,'Pager confirmation')`, tenant); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	txDo := func(f func(pgx.Tx) error) {
		t.Helper()
		if err := WithTenant(ctx, pool, tenant.String(), f); err != nil {
			t.Fatal(err)
		}
	}
	txDo(func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO notification_channels(tenant_id,id,name,channel_type,enabled,destination,recipients,revision,secret_version,created_at,updated_at) VALUES($1,'pager','Pager','jsm',true,'','[]',1,1,$2,$2)`, tenant, now); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO notification_channel_versions(tenant_id,channel_id,version,sealed_config,created_at) VALUES($1,'pager',1,'sealed',$2)`, tenant, now)
		return err
	})
	event := func(id string, rev int64, terminal bool) notification.Event {
		return notification.Event{TenantID: tenant, ID: shared.ID(id), Type: notification.EventFindingStatusChanged, SourceKind: "finding_status", SourceID: id, SchemaVersion: 1, OccurredAt: now, Data: json.RawMessage(`{}`), SubjectKind: "finding", SubjectID: "finding", PagerLifecycle: notification.PagerLifecycle{Episode: 1, Revision: rev, Terminal: terminal}}
	}
	d, err := repo.PublishToChannel(ctx, event("first", 1, false), "pager")
	if err != nil {
		t.Fatal(err)
	}
	claim := func(op string, fence int64, n int) {
		t.Helper()
		txDo(func(tx pgx.Tx) error {
			if _, e := tx.Exec(ctx, `UPDATE jobs SET status='claimed',claim_fence=$3,claimed_until=now()+interval '1 minute' WHERE tenant_id=$1 AND id=$2`, tenant, "notification-"+d.String(), fence); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx, `SELECT set_config('synapse.notification_pager_capability','pager-lifecycle-v1',true)`); e != nil {
				return e
			}
			_, e := tx.Exec(ctx, `INSERT INTO notification_delivery_attempts(tenant_id,id,delivery_id,attempt_number,started_at,outcome) VALUES($1,$2,$3,$4,now(),'started')`, tenant, op, d, n)
			return e
		})
	}
	claim("first-op", 1, 1)
	a, err := repo.AdmitPagerMutation(ctx, tenant, d, "notification-"+d.String(), 1, "first-op")
	if err != nil || a.Action != "send" {
		t.Fatalf("send %+v %v", a, err)
	}
	if err = repo.RecordPagerReceipt(ctx, tenant, d, "first-op", ports.NotificationSendResult{StatusCode: 202, ProviderRequestRef: "request"}); err != nil {
		t.Fatal(err)
	}
	if ids, e := repo.Publish(ctx, event("terminal", 2, true)); e != nil || len(ids) != 0 {
		t.Fatalf("terminal %v %v", ids, e)
	}
	txDo(func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `UPDATE notification_channels SET enabled=false WHERE tenant_id=$1 AND id='pager'`, tenant); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `UPDATE notification_deliveries SET state='cancelled',last_error='channel_disabled' WHERE tenant_id=$1 AND id=$2`, tenant, d); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `UPDATE jobs SET status='done',claimed_until=NULL WHERE tenant_id=$1 AND id=$2`, tenant, "notification-"+d.String()); e != nil {
			return e
		}
		return repo.reconcileTx(ctx, tx, tenant)
	})
	txDo(func(tx pgx.Tx) error {
		var status string
		if e := tx.QueryRow(ctx, `SELECT status FROM jobs WHERE tenant_id=$1 AND id=$2`, tenant, "notification-"+d.String()).Scan(&status); e != nil {
			return e
		}
		if status != "done" {
			t.Fatalf("disabled wake %s", status)
		}
		if _, e := tx.Exec(ctx, `UPDATE notification_channels SET enabled=true WHERE tenant_id=$1 AND id='pager'`, tenant); e != nil {
			return e
		}
		return repo.reconcileTx(ctx, tx, tenant)
	})
	txDo(func(tx pgx.Tx) error {
		var status string
		var fence int64
		if e := tx.QueryRow(ctx, `SELECT status,claim_fence FROM jobs WHERE tenant_id=$1 AND id=$2`, tenant, "notification-"+d.String()).Scan(&status, &fence); e != nil {
			return e
		}
		if status != "queued" || fence != 2 {
			t.Fatalf("resume %s %d", status, fence)
		}
		return nil
	})
	claim("poll-op", 2, 2)
	a, err = repo.AdmitPagerMutation(ctx, tenant, d, "notification-"+d.String(), 2, "poll-op")
	if err != nil || a.Action != "poll" || a.OperationID != "first-op" || a.ProviderRequestRef != "request" {
		t.Fatalf("poll %+v %v", a, err)
	}
	if err = repo.RecordPagerReceipt(ctx, tenant, d, "first-op", ports.NotificationSendResult{StatusCode: 200, RemoteRef: "alias"}); err != nil {
		t.Fatal(err)
	}
	txDo(func(tx pgx.Tx) error {
		var n int
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM notification_pager_operations WHERE tenant_id=$1 AND subject_id='finding' AND is_close`, tenant).Scan(&n); e != nil {
			return e
		}
		if n != 1 {
			t.Fatalf("close count %d", n)
		}
		return nil
	})
}
