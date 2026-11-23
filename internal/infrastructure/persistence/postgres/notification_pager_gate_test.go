package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

func TestPagerGateLateReceiptClosesOriginalEpisode(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	tenant := shared.ID("pager-gate")
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,'Pager')`, tenant); err != nil {
		t.Fatal(err)
	}
	err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO notification_channels(tenant_id,id,name,channel_type,enabled,destination,recipients,revision,secret_version,created_at,updated_at) VALUES($1,'pager','Pager','jsm',true,'','[]',1,1,$2,$2)`, tenant, now); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO notification_channel_versions(tenant_id,channel_id,version,sealed_config,created_at) VALUES($1,'pager',1,'sealed',$2)`, tenant, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	mk := func(id string, episode, revision int64, terminal bool) notification.Event {
		return notification.Event{TenantID: tenant, ID: shared.ID(id), Type: notification.EventFindingStatusChanged, SourceKind: "finding_status", SourceID: id, SchemaVersion: 1, OccurredAt: now, Data: json.RawMessage(`{}`), SubjectKind: "finding", SubjectID: "finding", PagerLifecycle: notification.PagerLifecycle{Episode: episode, Revision: revision, Terminal: terminal}}
	}
	trigger, err := repo.PublishToChannel(ctx, mk("create", 1, 1, false), "pager")
	if err != nil {
		t.Fatal(err)
	}
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `UPDATE jobs SET status='claimed',claim_fence=1,claimed_until=now()+interval '1 minute' WHERE tenant_id=$1 AND id=$2`, tenant, "notification-"+trigger.String()); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `SELECT set_config('synapse.notification_pager_capability','pager-lifecycle-v1',true)`); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `INSERT INTO notification_delivery_attempts(tenant_id,id,delivery_id,attempt_number,started_at,outcome) VALUES($1,'op-one',$2,1,now(),'started')`, tenant, trigger)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := repo.AdmitPagerMutation(ctx, tenant, trigger, "notification-"+trigger.String(), 1, "op-one")
	if err != nil || admitted.Action != "send" {
		t.Fatalf("admit=%+v err=%v", admitted, err)
	}
	if ids, err := repo.Publish(ctx, mk("close", 1, 2, true)); err != nil || len(ids) != 0 {
		t.Fatalf("terminal before receipt ids=%v err=%v", ids, err)
	}
	second, err := repo.PublishToChannel(ctx, mk("reopen", 2, 3, false), "pager")
	if err != nil || second == trigger {
		t.Fatalf("reopen %s %v", second, err)
	}
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE jobs SET claimed_until=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, tenant, "notification-"+trigger.String())
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	// A second worker cannot resend while the first submission is unresolved.
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `UPDATE jobs SET status='claimed',claim_fence=2,claimed_until=now()+interval '1 minute' WHERE tenant_id=$1 AND id=$2`, tenant, "notification-"+trigger.String()); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `SELECT set_config('synapse.notification_pager_capability','pager-lifecycle-v1',true)`); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `INSERT INTO notification_delivery_attempts(tenant_id,id,delivery_id,attempt_number,started_at,outcome) VALUES($1,'op-reclaim',$2,2,now(),'started')`, tenant, trigger)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	blockedReclaim, err := repo.AdmitPagerMutation(ctx, tenant, trigger, "notification-"+trigger.String(), 2, "op-reclaim")
	if err != nil || blockedReclaim.Action != "blocked" || blockedReclaim.Code != "pager_sending" {
		t.Fatalf("reclaim=%+v err=%v", blockedReclaim, err)
	}
	if err = repo.RecordPagerReceipt(ctx, tenant, trigger, "op-one", ports.NotificationSendResult{StatusCode: 202, ProviderRequestRef: "request-one", ErrorCode: "jsm_request_unconfirmed", Retryable: true}); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after the reclaimed worker dead-letters but before its callback.
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `UPDATE jobs SET status='failed',claimed_until=NULL WHERE tenant_id=$1 AND id=$2`, tenant, "notification-"+trigger.String()); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `UPDATE notification_deliveries SET state='dead_letter',last_error='pager_sending' WHERE tenant_id=$1 AND id=$2`, tenant, trigger); e != nil {
			return e
		}
		return repo.reconcileTx(ctx, tx, tenant)
	})
	if err != nil {
		t.Fatal(err)
	}
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		var status string
		var fence int64
		if e := tx.QueryRow(ctx, `SELECT status,claim_fence FROM jobs WHERE tenant_id=$1 AND id=$2`, tenant, "notification-"+trigger.String()).Scan(&status, &fence); e != nil {
			return e
		}
		if status != "queued" || fence != 3 {
			t.Fatalf("reconciliation status=%s fence=%d", status, fence)
		}
		if _, e := tx.Exec(ctx, `UPDATE jobs SET status='claimed',claimed_until=now()+interval '1 minute' WHERE tenant_id=$1 AND id=$2`, tenant, "notification-"+trigger.String()); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `SELECT set_config('synapse.notification_pager_capability','pager-lifecycle-v1',true)`); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `INSERT INTO notification_delivery_attempts(tenant_id,id,delivery_id,attempt_number,started_at,outcome) VALUES($1,'op-poll',$2,3,now(),'started')`, tenant, trigger)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	poll, err := repo.AdmitPagerMutation(ctx, tenant, trigger, "notification-"+trigger.String(), 3, "op-poll")
	if err != nil || poll.Action != "poll" || poll.OperationID != "op-one" || poll.ProviderRequestRef != "request-one" {
		t.Fatalf("poll=%+v err=%v", poll, err)
	}
	// Rotation after admission cannot erase an accepted in-flight result.
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `INSERT INTO notification_channel_versions(tenant_id,channel_id,version,sealed_config,created_at) VALUES($1,'pager',2,'replacement',now())`, tenant); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `UPDATE notification_channels SET secret_version=2 WHERE tenant_id=$1 AND id='pager'`, tenant)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.RecordPagerReceipt(ctx, tenant, trigger, "op-one", ports.NotificationSendResult{StatusCode: 202, RemoteRef: "alias-one"}); err != nil {
		t.Fatal(err)
	}
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		var triggerState, closeState, ref string
		var count int
		if e := tx.QueryRow(ctx, `SELECT state,remote_ref FROM notification_pager_operations WHERE tenant_id=$1 AND delivery_id=$2`, tenant, trigger).Scan(&triggerState, &ref); e != nil {
			return e
		}
		if e := tx.QueryRow(ctx, `SELECT state FROM notification_pager_operations WHERE tenant_id=$1 AND subject_kind='finding' AND subject_id='finding' AND episode=1 AND is_close`, tenant).Scan(&closeState); e != nil {
			return e
		}
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM notification_pager_operations WHERE tenant_id=$1 AND subject_id='finding' AND episode=2 AND NOT is_close`, tenant).Scan(&count); e != nil {
			return e
		}
		if triggerState != "done" || ref != "alias-one" || closeState != "pending" || count != 1 {
			t.Fatalf("states %s %s %s %d", triggerState, ref, closeState, count)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var closeDelivery shared.ID
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if e := tx.QueryRow(ctx, `SELECT delivery_id FROM notification_pager_operations WHERE tenant_id=$1 AND subject_id='finding' AND episode=1 AND is_close`, tenant).Scan(&closeDelivery); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `UPDATE jobs SET status='claimed',claim_fence=1,claimed_until=now()+interval '1 minute' WHERE tenant_id=$1 AND id=$2`, tenant, "notification-"+closeDelivery.String()); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `SELECT set_config('synapse.notification_pager_capability','pager-lifecycle-v1',true)`); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `INSERT INTO notification_delivery_attempts(tenant_id,id,delivery_id,attempt_number,started_at,outcome) VALUES($1,'op-close',$2,1,now(),'started')`, tenant, closeDelivery)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := repo.AdmitPagerMutation(ctx, tenant, closeDelivery, "notification-"+closeDelivery.String(), 1, "op-close")
	if err != nil || blocked.Action != "blocked" || blocked.Code != "pager_channel_unavailable" {
		t.Fatalf("rotation close=%+v err=%v", blocked, err)
	}

}

func TestPagerGateSerializesUpdatesAndRecoversLateDone(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	tenant := shared.ID("pager-lanes")
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,'Pager lanes')`, tenant); err != nil {
		t.Fatal(err)
	}
	err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `INSERT INTO notification_channels(tenant_id,id,name,channel_type,enabled,destination,recipients,revision,secret_version,created_at,updated_at) VALUES($1,'pager','Pager','pagerduty',true,'','[]',1,1,$2,$2)`, tenant, now); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `INSERT INTO notification_channel_versions(tenant_id,channel_id,version,sealed_config,created_at) VALUES($1,'pager',1,'sealed',$2)`, tenant, now)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	mk := func(id string, revision int64, terminal bool) notification.Event {
		return notification.Event{TenantID: tenant, ID: shared.ID(id), Type: notification.EventFindingStatusChanged, SourceKind: "finding_status", SourceID: id, SchemaVersion: 1, OccurredAt: now, Data: json.RawMessage(`{}`), SubjectKind: "finding", SubjectID: "finding", PagerLifecycle: notification.PagerLifecycle{Episode: 1, Revision: revision, Terminal: terminal}}
	}
	claim := func(delivery shared.ID, op string, fence int64, number int) {
		t.Helper()
		err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			if _, e := tx.Exec(ctx, `UPDATE jobs SET status='claimed',claim_fence=$3,claimed_until=now()+interval '1 minute' WHERE tenant_id=$1 AND id=$2`, tenant, "notification-"+delivery.String(), fence); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx, `SELECT set_config('synapse.notification_pager_capability','pager-lifecycle-v1',true)`); e != nil {
				return e
			}
			_, e := tx.Exec(ctx, `INSERT INTO notification_delivery_attempts(tenant_id,id,delivery_id,attempt_number,started_at,outcome) VALUES($1,$2,$3,$4,now(),'started')`, tenant, op, delivery, number)
			return e
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	first, err := repo.PublishToChannel(ctx, mk("first", 1, false), "pager")
	if err != nil {
		t.Fatal(err)
	}
	claim(first, "first-op", 1, 1)
	a, err := repo.AdmitPagerMutation(ctx, tenant, first, "notification-"+first.String(), 1, "first-op")
	if err != nil || a.Action != "send" {
		t.Fatalf("first=%+v %v", a, err)
	}
	second, err := repo.PublishToChannel(ctx, mk("second", 2, false), "pager")
	if err != nil || first == second {
		t.Fatalf("second=%s err=%v", second, err)
	}
	claim(second, "second-wait", 1, 1)
	a, err = repo.AdmitPagerMutation(ctx, tenant, second, "notification-"+second.String(), 1, "second-wait")
	if err != nil || a.Code != "pager_waiting" {
		t.Fatalf("waiting=%+v %v", a, err)
	}
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `UPDATE jobs SET status='failed',claimed_until=NULL WHERE tenant_id=$1 AND id=$2`, tenant, "notification-"+second.String()); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `UPDATE notification_deliveries SET state='dead_letter',last_error='pager_waiting' WHERE tenant_id=$1 AND id=$2`, tenant, second)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	// The late provider success arrives after cancellation and queue completion.
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `UPDATE jobs SET status='done',claimed_until=NULL WHERE tenant_id=$1 AND id=$2`, tenant, "notification-"+first.String()); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `UPDATE notification_deliveries SET state='cancelled',last_error='channel_disabled' WHERE tenant_id=$1 AND id=$2`, tenant, first)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.RecordPagerReceipt(ctx, tenant, first, "first-op", ports.NotificationSendResult{StatusCode: 202, RemoteRef: "alias"}); err != nil {
		t.Fatal(err)
	}
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error { return repo.reconcileTx(ctx, tx, tenant) })
	if err != nil {
		t.Fatal(err)
	}
	claim(second, "second-send", 2, 2)
	a, err = repo.AdmitPagerMutation(ctx, tenant, second, "notification-"+second.String(), 2, "second-send")
	if err != nil || a.Action != "send" {
		t.Fatalf("second send=%+v %v", a, err)
	}
	ids, err := repo.Publish(ctx, mk("terminal", 3, true))
	if err != nil || len(ids) != 0 {
		t.Fatalf("premature close=%v %v", ids, err)
	}
	if err = repo.RecordPagerReceipt(ctx, tenant, second, "second-send", ports.NotificationSendResult{StatusCode: 400, ErrorCode: "http_400"}); err != nil {
		t.Fatal(err)
	}
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		var n int
		if e := tx.QueryRow(ctx, `SELECT count(*) FROM notification_pager_operations WHERE tenant_id=$1 AND is_close`, tenant).Scan(&n); e != nil {
			return e
		}
		if n != 1 {
			t.Fatalf("close count=%d", n)
		}
		if _, e := tx.Exec(ctx, `UPDATE jobs SET status='done',claimed_until=NULL WHERE tenant_id=$1 AND id=$2`, tenant, "notification-"+first.String()); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `UPDATE notification_deliveries SET state='cancelled',last_error='channel_disabled' WHERE tenant_id=$1 AND id=$2`, tenant, first); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `UPDATE notification_channels SET enabled=false WHERE tenant_id=$1 AND id='pager'`, tenant); e != nil {
			return e
		}
		return repo.reconcileTx(ctx, tx, tenant)
	})
	if err != nil {
		t.Fatal(err)
	}
	err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE jobs SET status='claimed',claimed_until=now()+interval '1 minute' WHERE tenant_id=$1 AND id=$2 AND status='queued'`, tenant, "notification-"+first.String())
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	ok, err := repo.ReconcilePagerAcknowledgement(ctx, tenant, first, "notification-"+first.String(), 3)
	if err != nil || !ok {
		t.Fatalf("reconcile done=%v %v", ok, err)
	}
	got, err := repo.GetDelivery(ctx, tenant, first)
	if err != nil || got.State != notification.DeliverySucceeded || got.RemoteRef != "alias" {
		t.Fatalf("delivery=%+v %v", got, err)
	}
}
