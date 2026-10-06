package postgres

import (
	"context"
	"encoding/json"
	"errors"
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

	if _, err := a.repo.BeginAttempt(a.ctx, a.tenant, did, job.ID, job.Fence, "after-load-attempt", a.now.Add(2*time.Second)); !errors.Is(err, ports.ErrRetryable) {
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
	if _, err := a.repo.BeginAttempt(a.ctx, a.tenant, did, job.ID, job.Fence, "started-attempt", a.now); err != nil {
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
		_, err := a.repo.BeginAttempt(a.ctx, a.tenant, did, job.ID, job.Fence, "serialized-attempt", a.now)
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
