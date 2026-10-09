package postgres

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
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
