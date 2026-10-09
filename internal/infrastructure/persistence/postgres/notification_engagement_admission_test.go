package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// engagementAdmission is one tenant with an engagement and a webhook channel, for the #1360 checks
// of an engagement override at attempt admission.
type engagementAdmission struct {
	ctx    context.Context
	tenant shared.ID
	pool   *pgxpool.Pool
	repo   *NotificationRepository
	queue  *JobQueue
	now    time.Time
}

func newEngagementAdmission(t *testing.T, tenant shared.ID, engagements ...string) *engagementAdmission {
	t.Helper()
	pool := notificationTestPool(t)
	a := &engagementAdmission{ctx: shared.WithTenant(context.Background(), tenant), tenant: tenant, pool: pool, repo: NewNotificationRepository(pool),
		queue: NewJobQueue(pool, &notificationTestIDs{}), now: time.Now().UTC().Truncate(time.Microsecond)}
	if _, err := pool.Exec(a.ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
		t.Fatal(err)
	}
	for _, engagement := range engagements {
		if err := WithTenant(a.ctx, pool, tenant.String(), func(tx pgx.Tx) error {
			_, err := tx.Exec(a.ctx, `INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,$1)`, engagement, tenant)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	channel := notification.Channel{TenantID: tenant, ID: "channel", Name: "Hook", Type: notification.ChannelWebhook, Enabled: true, Revision: 1, SecretVersion: 1, CreatedAt: a.now, UpdatedAt: a.now}
	if _, err := a.repo.CreateChannel(a.ctx, channel, "sealed"); err != nil {
		t.Fatal(err)
	}
	return a
}

// claimed publishes an event about engagement and claims its delivery job.
func (a *engagementAdmission) claimed(t *testing.T, source, engagement string) (shared.ID, *ports.QueuedJob) {
	t.Helper()
	did, err := a.repo.PublishToChannel(a.ctx, notification.Event{TenantID: a.tenant, ID: shared.ID(source), Type: notification.EventTest, SourceKind: "test",
		SourceID: source, EngagementID: shared.ID(engagement), SchemaVersion: 1, OccurredAt: a.now, Data: json.RawMessage(`{"title":"test"}`)}, "channel")
	if err != nil {
		t.Fatal(err)
	}
	job, err := a.queue.Claim(a.ctx, time.Minute, "notification.deliver")
	if err != nil || job == nil {
		t.Fatalf("claim: %v", err)
	}
	return did, job
}

func (a *engagementAdmission) setNone(t *testing.T, engagement string, revision int) {
	t.Helper()
	at := a.now.Add(time.Second)
	if _, err := a.repo.PutEngagementNotificationSetting(a.ctx, notification.EngagementNotificationSetting{TenantID: a.tenant, EngagementID: shared.ID(engagement),
		ExternalNotifications: notification.EngagementNotificationsNone, Revision: revision, UpdatedAt: &at, UpdatedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
}

// TestNotificationPostgresEngagementNoneAfterLoadStopsTheAttempt is the interleaving of the #1360
// review: the worker loads the work while the engagement inherits, an operator commits none, and
// only then does the worker try to start the attempt. Nothing may be admitted, and the delivery is
// cancelled with engagement_suppressed.
func TestNotificationPostgresEngagementNoneAfterLoadStopsTheAttempt(t *testing.T) {
	a := newEngagementAdmission(t, "admission-after-load", "admission-after-load-eng")
	did, job := a.claimed(t, "after-load", "admission-after-load-eng")
	work, err := a.repo.LoadWork(a.ctx, a.tenant, did)
	if err != nil || work.Engagement != notification.EngagementNotificationsInherit {
		t.Fatalf("load = %q, %v", work.Engagement, err)
	}

	a.setNone(t, "admission-after-load-eng", 1)

	if _, err := a.repo.BeginAttempt(a.ctx, a.tenant, did, job.ID, job.Fence, "after-load-attempt", a.now.Add(2*time.Second), ports.AttemptAdmission{}); !errors.Is(err, ports.ErrRetryable) {
		t.Fatalf("begin attempt after none = %v, want ErrRetryable", err)
	}
	if attempts, err := a.repo.ListAttempts(a.ctx, a.tenant, did); err != nil || len(attempts) != 0 {
		t.Fatalf("attempts = %+v, %v, want none", attempts, err)
	}
	d, err := a.repo.GetDelivery(a.ctx, a.tenant, did)
	if err != nil || d.State != notification.DeliveryCancelled || d.LastError != notification.CodeEngagementSuppressed {
		t.Fatalf("delivery = %+v, %v, want cancelled with engagement_suppressed", d, err)
	}
}

// TestNotificationPostgresEngagementNoneLeavesAStartedAttempt checks the other order: an attempt
// admitted before none committed is in flight, so the write leaves its delivery open.
func TestNotificationPostgresEngagementNoneLeavesAStartedAttempt(t *testing.T) {
	a := newEngagementAdmission(t, "admission-started", "admission-started-eng")
	did, job := a.claimed(t, "started", "admission-started-eng")
	if _, err := a.repo.BeginAttempt(a.ctx, a.tenant, did, job.ID, job.Fence, "started-attempt", a.now, ports.AttemptAdmission{}); err != nil {
		t.Fatal(err)
	}

	a.setNone(t, "admission-started-eng", 1)

	d, err := a.repo.GetDelivery(a.ctx, a.tenant, did)
	if err != nil || d.State == notification.DeliveryCancelled {
		t.Fatalf("delivery with a started attempt = %+v, %v, want it left open", d, err)
	}
}

// TestNotificationPostgresEngagementWriteSerializesAdmission holds a first settings write open (no
// row exists yet to lock) and starts an admission meanwhile. The admission must wait for the write
// and then read its none, rather than read the missing row as inherit and send.
func TestNotificationPostgresEngagementWriteSerializesAdmission(t *testing.T) {
	a := newEngagementAdmission(t, "admission-serialized", "admission-serialized-eng")
	did, job := a.claimed(t, "serialized", "admission-serialized-eng")

	writer, err := a.pool.Begin(a.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Rollback(context.Background()) }()
	if _, err := writer.Exec(a.ctx, `SELECT set_config('app.current_tenant',$1,true)`, a.tenant); err != nil {
		t.Fatal(err)
	}
	if err := lockEngagementSetting(a.ctx, writer, a.tenant, "admission-serialized-eng", true); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(a.ctx, `INSERT INTO notification_engagement_settings(tenant_id,engagement_id,external_notifications,revision,updated_at,updated_by) VALUES($1,'admission-serialized-eng','none',1,now(),'admin')`, a.tenant); err != nil {
		t.Fatal(err)
	}

	admitted := make(chan error, 1)
	go func() {
		_, err := a.repo.BeginAttempt(a.ctx, a.tenant, did, job.ID, job.Fence, "serialized-attempt", a.now, ports.AttemptAdmission{})
		admitted <- err
	}()
	select {
	case err := <-admitted:
		t.Fatalf("admission did not wait for the open settings write: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := writer.Commit(a.ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-admitted:
		if !errors.Is(err, ports.ErrRetryable) {
			t.Fatalf("admission after the committed none = %v, want ErrRetryable", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("admission still blocked after the write committed")
	}
	if attempts, err := a.repo.ListAttempts(a.ctx, a.tenant, did); err != nil || len(attempts) != 0 {
		t.Fatalf("attempts = %+v, %v, want none", attempts, err)
	}
}

// TestNotificationPostgresAdmissionRefusesALoweredClass is the #1566 review case in Postgres: a
// message rendered at summary is refused once the engagement is capped at signal, and once the
// channel itself is lowered to signal, while a message rendered at signal starts.
func TestNotificationPostgresAdmissionRefusesALoweredClass(t *testing.T) {
	a := newEngagementAdmission(t, "admission-class", "admission-class-eng", "admission-class-other")
	summary := ports.AttemptAdmission{DataClass: notification.DataClassSummary}

	capped, cappedJob := a.claimed(t, "capped", "admission-class-eng")
	at := a.now.Add(time.Second)
	if _, err := a.repo.PutEngagementNotificationSetting(a.ctx, notification.EngagementNotificationSetting{TenantID: a.tenant, EngagementID: "admission-class-eng",
		ExternalNotifications: notification.EngagementNotificationsSignal, Revision: 1, UpdatedAt: &at, UpdatedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.repo.BeginAttempt(a.ctx, a.tenant, capped, cappedJob.ID, cappedJob.Fence, "capped-attempt", a.now, summary); !errors.Is(err, ports.ErrRetryable) {
		t.Fatalf("summary under a signal engagement = %v, want ErrRetryable", err)
	}
	if _, err := a.repo.BeginAttempt(a.ctx, a.tenant, capped, cappedJob.ID, cappedJob.Fence, "capped-signal", a.now,
		ports.AttemptAdmission{DataClass: notification.DataClassSignal}); err != nil {
		t.Fatalf("signal under a signal engagement = %v, want admitted", err)
	}

	// The channel is lowered in the same transaction shape UpdateChannel uses: a row update the
	// admission's FOR UPDATE read waits for.
	lowered, loweredJob := a.claimed(t, "lowered", "admission-class-other")
	if err := WithTenant(a.ctx, a.pool, a.tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(a.ctx, `UPDATE notification_channels SET data_class='signal',revision=revision+1 WHERE tenant_id=$1 AND id='channel'`, a.tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	later := a.now.Add(2 * time.Second)
	if _, err := a.repo.BeginAttempt(a.ctx, a.tenant, lowered, loweredJob.ID, loweredJob.Fence, "lowered-attempt", later, summary); !errors.Is(err, ports.ErrRetryable) {
		t.Fatalf("summary on a channel lowered to signal = %v, want ErrRetryable", err)
	}
	if attempts, err := a.repo.ListAttempts(a.ctx, a.tenant, lowered); err != nil || len(attempts) != 0 {
		t.Fatalf("attempts = %+v, %v, want none", attempts, err)
	}
}

func TestNotificationPostgresAdmissionRevalidatesRenderedDataClass(t *testing.T) {
	a := newEngagementAdmission(t, "admission-class", "admission-class-eng")
	for i, tc := range []struct {
		name       string
		rendered   notification.DataClass
		channel    notification.DataClass
		engagement notification.EngagementNotifications
		wantErr    error
	}{
		{"engagement lowered", notification.DataClassSummary, notification.DataClassSummary, notification.EngagementNotificationsSignal, ports.ErrRetryable},
		{"channel lowered", notification.DataClassSummary, notification.DataClassSignal, notification.EngagementNotificationsInherit, ports.ErrRetryable},
		{"detail lowered to summary", notification.DataClassDetail, notification.DataClassSummary, notification.EngagementNotificationsInherit, ports.ErrRetryable},
		{"unchanged", notification.DataClassSummary, notification.DataClassSummary, notification.EngagementNotificationsInherit, nil},
		{"policy raised", notification.DataClassSignal, notification.DataClassSummary, notification.EngagementNotificationsInherit, nil},
		{"already capped", notification.DataClassSignal, notification.DataClassDetail, notification.EngagementNotificationsSignal, nil},
		{"legacy empty class", "", notification.DataClassSummary, notification.EngagementNotificationsInherit, nil},
		{"invalid rendered class", "unknown", notification.DataClassSummary, notification.EngagementNotificationsInherit, shared.ErrValidation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Space publications past the targeted-channel test rate limit and admission budgets.
			a.now = a.now.Add(time.Minute)
			did, job := a.claimed(t, fmt.Sprintf("class-%d", i), "admission-class-eng")
			channel, err := a.repo.GetChannel(a.ctx, a.tenant, "channel")
			if err != nil {
				t.Fatal(err)
			}
			channel.DataClass, channel.Revision = tc.channel, channel.Revision+1
			if _, err := a.repo.UpdateChannel(a.ctx, channel, "", false); err != nil {
				t.Fatal(err)
			}
			if _, err := a.repo.PutEngagementNotificationSetting(a.ctx, notification.EngagementNotificationSetting{TenantID: a.tenant, EngagementID: "admission-class-eng", ExternalNotifications: tc.engagement, Revision: i + 1, UpdatedAt: &a.now, UpdatedBy: "admin"}); err != nil {
				t.Fatal(err)
			}
			_, err = a.repo.BeginAttempt(a.ctx, a.tenant, did, job.ID, job.Fence, shared.ID(fmt.Sprintf("attempt-%d", i)), a.now, ports.AttemptAdmission{TemplateRef: "tenant:template@1", DataClass: tc.rendered})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("admission = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				delivery, err := a.repo.GetDelivery(a.ctx, a.tenant, did)
				if err != nil || delivery.Attempts != 0 || delivery.TemplateRef != "" || delivery.State != notification.DeliveryPending {
					t.Fatalf("refused delivery=%+v, %v", delivery, err)
				}
				if attempts, err := a.repo.ListAttempts(a.ctx, a.tenant, did); err != nil || len(attempts) != 0 {
					t.Fatalf("refused attempts=%+v, %v", attempts, err)
				}
				if _, err := a.repo.BeginAttempt(a.ctx, a.tenant, did, job.ID, job.Fence, shared.ID(fmt.Sprintf("safe-%d", i)), a.now, ports.AttemptAdmission{TemplateRef: "tenant:template@1", DataClass: notification.DataClassSignal}); err != nil {
					t.Fatalf("safe admission at the same time must preserve both rate budgets: %v", err)
				}
			}
			if err := a.queue.Complete(a.ctx, job.ID, job.Fence); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNotificationPostgresPolicyLoweringSerializesAdmission(t *testing.T) {
	for _, policy := range []string{"engagement", "channel"} {
		t.Run(policy, func(t *testing.T) {
			a := newEngagementAdmission(t, shared.ID("admission-cap-"+policy), "admission-cap-eng")
			did, job := a.claimed(t, "cap", "admission-cap-eng")
			writer, err := a.pool.Begin(a.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = writer.Rollback(context.Background()) }()
			if _, err := writer.Exec(a.ctx, `SELECT set_config('app.current_tenant',$1,true)`, a.tenant); err != nil {
				t.Fatal(err)
			}
			var writerPID int
			if err := writer.QueryRow(a.ctx, `SELECT pg_backend_pid()`).Scan(&writerPID); err != nil {
				t.Fatal(err)
			}
			if policy == "engagement" {
				if err := lockEngagementSetting(a.ctx, writer, a.tenant, "admission-cap-eng", true); err != nil {
					t.Fatal(err)
				}
				_, err = writer.Exec(a.ctx, `INSERT INTO notification_engagement_settings(tenant_id,engagement_id,external_notifications,revision,updated_at,updated_by) VALUES($1,'admission-cap-eng','signal',1,now(),'admin')`, a.tenant)
			} else {
				_, err = writer.Exec(a.ctx, `UPDATE notification_channels SET data_class='signal',revision=revision+1 WHERE tenant_id=$1 AND id='channel'`, a.tenant)
			}
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
			defer cancel()
			admitted := make(chan error, 1)
			go func() {
				_, err := a.repo.BeginAttempt(ctx, a.tenant, did, job.ID, job.Fence, "stale-attempt", a.now, ports.AttemptAdmission{TemplateRef: "tenant:template@1", DataClass: notification.DataClassSummary})
				admitted <- err
			}()
			// Wait for actual database lock contention, rather than assume the goroutine started.
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				var blocked bool
				if err := a.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, writerPID).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
				select {
				case err := <-admitted:
					t.Fatalf("admission did not wait for the policy write: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-ticker.C:
				}
			}
			if err := writer.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-admitted:
				if !errors.Is(err, ports.ErrRetryable) {
					t.Fatalf("admission after policy commit = %v, want ErrRetryable", err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if attempts, err := a.repo.ListAttempts(a.ctx, a.tenant, did); err != nil || len(attempts) != 0 {
				t.Fatalf("refused attempts=%+v, %v", attempts, err)
			}
			if _, err := a.repo.BeginAttempt(a.ctx, a.tenant, did, job.ID, job.Fence, "safe-attempt", a.now, ports.AttemptAdmission{TemplateRef: "tenant:template@1", DataClass: notification.DataClassSignal}); err != nil {
				t.Fatalf("safe admission after serialized refusal: %v", err)
			}
		})
	}
}
