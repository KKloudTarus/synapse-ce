package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/jackc/pgx/v5"
)

func TestNotificationOldestPendingAcrossTenantRLS(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		"INSERT INTO tenants(id,name) VALUES('metrics-tenant-a','A'),('metrics-tenant-b','B')"); err != nil {
		t.Fatal(err)
	}
	repo := NewNotificationRepository(pool)
	if empty, err := repo.NotificationOldestPending(ctx); err != nil || len(empty) != 0 {
		t.Fatalf("initial pending=%v err=%v; want empty", empty, err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	newChannel := func(tenant shared.ID, id string, typ notification.ChannelType) notification.Channel {
		t.Helper()
		ch := notification.Channel{
			TenantID: tenant, ID: shared.ID(id), Name: id, Type: typ,
			Enabled: true, Revision: 1, SecretVersion: 1,
			CreatedAt: now, UpdatedAt: now,
		}
		if _, err := repo.CreateChannel(shared.WithTenant(ctx, tenant), ch, "sealed"); err != nil {
			t.Fatal(err)
		}
		return ch
	}
	publish := func(ch notification.Channel, id string) notification.Delivery {
		t.Helper()
		tenantCtx := shared.WithTenant(ctx, ch.TenantID)
		did, err := repo.PublishToChannel(tenantCtx, notification.Event{
			TenantID: ch.TenantID, ID: shared.ID(id), Type: notification.EventTest,
			SourceKind: "metrics-test", SourceID: id, SchemaVersion: 1,
			OccurredAt: now, Data: json.RawMessage(`{"title":"test"}`),
		}, ch.ID)
		if err != nil {
			t.Fatal(err)
		}
		d, err := repo.GetDelivery(tenantCtx, ch.TenantID, did)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	a := shared.ID("metrics-tenant-a")
	b := shared.ID("metrics-tenant-b")
	first := publish(newChannel(a, "webhook-a", notification.ChannelWebhook), "delivery-a")
	time.Sleep(5 * time.Millisecond)
	other := publish(newChannel(b, "webhook-b", notification.ChannelWebhook), "delivery-b")
	slack := publish(newChannel(b, "slack-b", notification.ChannelSlack), "delivery-slack")

	got, err := repo.NotificationOldestPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("pending families=%v, want webhook and Slack", got)
	}
	if !got[notification.ChannelWebhook].Equal(first.CreatedAt) {
		t.Fatalf("oldest webhook=%s want=%s (other tenant=%s)",
			got[notification.ChannelWebhook], first.CreatedAt, other.CreatedAt)
	}
	if !got[notification.ChannelSlack].Equal(slack.CreatedAt) {
		t.Fatalf("oldest Slack=%s want=%s", got[notification.ChannelSlack], slack.CreatedAt)
	}
	if !first.CreatedAt.Before(other.CreatedAt) {
		t.Fatalf("fixture failed to order pending deliveries: %s >= %s", first.CreatedAt, other.CreatedAt)
	}

	// A tenant-scoped transaction cannot see or count B's delivery. The
	// aggregate uses independent RLS-scoped transactions, not a cross-tenant
	// query on notification_deliveries.
	err = WithTenant(ctx, pool, a.String(), func(tx pgx.Tx) error {
		var visible int
		if err := tx.QueryRow(ctx,
			"SELECT count(*) FROM notification_deliveries WHERE tenant_id=$1", b).Scan(&visible); err != nil {
			return err
		}
		if visible != 0 {
			t.Errorf("cross-tenant delivery rows visible: %d", visible)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	partial, err := repo.NotificationOldestPending(cancelled)
	if !errors.Is(err, context.Canceled) || partial != nil {
		t.Fatalf("cancelled scrape returned partial ages=%v, err=%v", partial, err)
	}
}

// A second worker may issue the same dead-letter callback before the first
// transaction commits. Only the callback that updates the row may count it.
func TestNotificationDeadLetterConcurrentPostgres(t *testing.T) {
	pool := notificationTestPool(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,name) VALUES('metrics-dead','Dead')"); err != nil {
		t.Fatal(err)
	}
	tenant := shared.ID("metrics-dead")
	tenantCtx := shared.WithTenant(ctx, tenant)
	now := time.Now().UTC()
	repo := NewNotificationRepository(pool)
	channel := notification.Channel{
		TenantID: tenant, ID: "hook", Name: "hook", Type: notification.ChannelWebhook,
		Enabled: true, Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now,
	}
	if _, err := repo.CreateChannel(tenantCtx, channel, "sealed"); err != nil {
		t.Fatal(err)
	}
	did, err := repo.PublishToChannel(tenantCtx, notification.Event{
		TenantID: tenant, ID: "event", Type: notification.EventTest,
		SourceKind: "metrics-test", SourceID: "terminal", SchemaVersion: 1,
		OccurredAt: now, Data: json.RawMessage(`{"title":"test"}`),
	}, channel.ID)
	if err != nil {
		t.Fatal(err)
	}
	queue := NewJobQueue(pool, &notificationTestIDs{})
	job, err := queue.Claim(ctx, time.Minute, "notification.deliver")
	if err != nil || job == nil || job.TenantID != tenant {
		t.Fatalf("claim=%+v err=%v", job, err)
	}
	if err := queue.Deadletter(tenantCtx, job.ID, job.Fence); err != nil {
		t.Fatal(err)
	}

	const callbacks = 16
	changed := make(chan bool, callbacks)
	errors := make(chan error, callbacks)
	var wg sync.WaitGroup
	for i := 0; i < callbacks; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := repo.DeadLetterDelivery(tenantCtx, tenant, did, job.Fence, "worker_dead_letter")
			changed <- ok
			errors <- err
		}()
	}
	wg.Wait()
	close(changed)
	close(errors)
	count := 0
	for callErr := range errors {
		if callErr != nil {
			t.Fatal(callErr)
		}
	}
	for ok := range changed {
		if ok {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("concurrent dead-letter calls yielded %d transitions, want 1", count)
	}
	delivery, err := repo.GetDelivery(tenantCtx, tenant, did)
	if err != nil || delivery.State != notification.DeliveryDead {
		t.Fatalf("terminal delivery=%+v err=%v", delivery, err)
	}
	var intents int
	if err := WithTenant(tenantCtx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(tenantCtx, "SELECT count(*) FROM notification_audit_intents WHERE delivery_id=$1", did).Scan(&intents)
	}); err != nil || intents != 1 {
		t.Fatalf("audit intents=%d err=%v, want 1", intents, err)
	}
}
