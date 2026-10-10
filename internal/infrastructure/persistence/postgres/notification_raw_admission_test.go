package postgres

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestRawWebhookAdmissionRechecksCommittedOptIn(t *testing.T) {
	a := newEngagementAdmission(t, "raw-admission")
	setRaw := func(raw bool) {
		t.Helper()
		if err := WithTenant(a.ctx, a.pool, a.tenant.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(a.ctx, `UPDATE notification_channels SET data_class='detail',raw_event=$1 WHERE id='channel'`, raw)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	setRaw(true)
	did, job := a.claimed(t, "raw-loaded", "")
	work, err := a.repo.LoadWork(a.ctx, a.tenant, did)
	if err != nil || !work.Channel.RawEvent {
		t.Fatalf("loaded raw=%v err=%v", work.Channel.RawEvent, err)
	}
	setRaw(false)
	if _, err := a.repo.BeginAttempt(a.ctx, a.tenant, did, job.ID, job.Fence, "stale-raw", a.now, ports.AttemptAdmission{DataClass: notification.DataClassDetail, RawEvent: true}); !errors.Is(err, ports.ErrRetryable) {
		t.Fatalf("stale raw admission=%v", err)
	}
	attempts, err := a.repo.ListAttempts(a.ctx, a.tenant, did)
	if err != nil || len(attempts) != 0 {
		t.Fatalf("rejected raw attempts=%+v err=%v", attempts, err)
	}
	if _, err := a.repo.BeginAttempt(a.ctx, a.tenant, did, job.ID, job.Fence, "filtered-detail", a.now, ports.AttemptAdmission{DataClass: notification.DataClassDetail}); err != nil {
		t.Fatalf("filtered retry=%v", err)
	}
}

func TestWebhookAttemptFenceRejectsLegacyInsertAndAdmitsCurrentPolicy(t *testing.T) {
	a := newEngagementAdmission(t, "webhook-attempt-fence")
	did, job := a.claimed(t, "legacy-attempt", "")
	err := WithTenant(a.ctx, a.pool, a.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(a.ctx, `INSERT INTO notification_delivery_attempts(tenant_id,id,delivery_id,attempt_number,started_at,outcome)
			VALUES($1,'legacy-attempt',$2,1,$3,'started')`, a.tenant, did, a.now)
		return err
	})
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "55000" {
		t.Fatalf("legacy webhook attempt err=%v, want SQLSTATE 55000", err)
	}
	if attempts, err := a.repo.ListAttempts(a.ctx, a.tenant, did); err != nil || len(attempts) != 0 {
		t.Fatalf("legacy attempt rows=%+v err=%v", attempts, err)
	}
	if _, err := a.repo.BeginAttempt(a.ctx, a.tenant, did, job.ID, job.Fence, "current-attempt", a.now, ports.AttemptAdmission{DataClass: notification.DataClassSignal}); err != nil {
		t.Fatalf("current webhook admission: %v", err)
	}
	v2Delivery, err := a.repo.PublishToChannel(a.ctx, notification.Event{TenantID: a.tenant, ID: "v2-attempt", Type: notification.EventScanCompleted, SourceKind: "scan_job", SourceID: "v2-attempt", SchemaVersion: 2, OccurredAt: a.now.Add(time.Second), Data: json.RawMessage(`{}`)}, "channel")
	if err != nil {
		t.Fatalf("publish v2 delivery: %v", err)
	}
	v2Job, err := a.queue.Claim(a.ctx, time.Minute, "notification.deliver")
	if err != nil || v2Job == nil {
		t.Fatalf("claim v2 delivery: job=%+v err=%v", v2Job, err)
	}
	if _, err := a.repo.BeginAttempt(a.ctx, a.tenant, v2Delivery, v2Job.ID, v2Job.Fence, "current-v2-attempt", a.now.Add(2*time.Second), ports.AttemptAdmission{DataClass: notification.DataClassSignal}); err != nil {
		t.Fatalf("current v2 webhook admission: %v", err)
	}
	if err := WithTenant(a.ctx, a.pool, a.tenant.String(), func(tx pgx.Tx) error {
		var marker string
		if err := tx.QueryRow(a.ctx, `SELECT COALESCE(current_setting('synapse.notification_delivery_capability',true),'')`).Scan(&marker); err != nil {
			return err
		}
		if marker != "" {
			t.Fatalf("delivery capability leaked between transactions: %q", marker)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
