package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// newCancellationFixture creates a channel, a matching rule, and one pending delivery against
// them. id names both the channel and the rule, so each subtest can use its own without
// colliding with another subtest's deliveries.
func newCancellationFixture(t *testing.T, pool *pgxpool.Pool, tenant shared.ID, id shared.ID) (repo *NotificationRepository, ctx context.Context, channel notification.Channel, delivery shared.ID, now time.Time) {
	t.Helper()
	repo = NewNotificationRepository(pool)
	ctx = shared.WithTenant(context.Background(), tenant)
	now = time.Now().UTC().Truncate(time.Microsecond)
	c := notification.Channel{
		TenantID: tenant, ID: id, Name: string(id), Type: notification.ChannelWebhook, Enabled: true,
		Destination: "https://example.test/" + id.String(), Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now,
	}
	channel, err := repo.CreateChannel(ctx, c, "sealed-v1")
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}
	rule := notification.Rule{
		TenantID: tenant, ID: id, Name: string(id), Enabled: true, EventType: notification.EventVulnerabilityAction,
		ChannelIDs: []shared.ID{id}, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	if _, err := repo.CreateRule(ctx, rule); err != nil {
		t.Fatalf("create rule: %v", err)
	}
	// Every subtest shares one tenant and event type, so a rule left behind would also match the
	// next subtest's event and fan out to this subtest's (by-then unrelated) channel too.
	t.Cleanup(func() {
		if err := repo.DeleteRule(context.Background(), tenant, id, 1); err != nil {
			t.Errorf("cleanup: delete rule %s: %v", id, err)
		}
	})
	event := notification.Event{
		TenantID: tenant, ID: shared.ID("event-" + id.String()), Type: notification.EventVulnerabilityAction,
		SourceKind: "risk-test", SourceID: "risk-" + id.String(), Severity: shared.SeverityHigh, SchemaVersion: 1,
		OccurredAt: now, Data: json.RawMessage(`{"title":"High risk"}`),
	}
	deliveries, err := repo.Publish(ctx, event)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("publish: deliveries=%v err=%v", deliveries, err)
	}
	delivery = deliveries[0]
	d, err := repo.GetDelivery(ctx, tenant, delivery)
	if err != nil || d.State != notification.DeliveryPending {
		t.Fatalf("precondition: delivery state=%s err=%v, want pending", d.State, err)
	}
	return repo, ctx, channel, delivery, now
}

// startAttempt gives delivery a live attempt, directly, so the guard that leaves a started
// attempt's delivery alone can be tested without a real job-queue claim.
func startAttempt(t *testing.T, pool *pgxpool.Pool, tenant, delivery shared.ID, at time.Time) {
	t.Helper()
	err := WithTenant(context.Background(), pool, tenant.String(), func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `SELECT set_config('synapse.notification_delivery_capability','current-filter-v1',true)`); err != nil {
			return err
		}
		_, err := tx.Exec(context.Background(), `INSERT INTO notification_delivery_attempts(tenant_id,id,delivery_id,attempt_number,started_at,outcome) VALUES($1,$2,$3,1,$4,'started')`,
			tenant, "attempt-"+delivery.String(), delivery, at)
		return err
	})
	if err != nil {
		t.Fatalf("start attempt: %v", err)
	}
}

func assertCancelled(t *testing.T, repo *NotificationRepository, ctx context.Context, tenant, delivery shared.ID, reason string) {
	t.Helper()
	d, err := repo.GetDelivery(ctx, tenant, delivery)
	if err != nil {
		t.Fatalf("get delivery: %v", err)
	}
	if d.State != notification.DeliveryCancelled || d.LastError != reason || d.NextAttemptAt != nil {
		t.Fatalf("delivery = %+v, want cancelled with %q and no next attempt", d, reason)
	}
}

func assertStillPending(t *testing.T, repo *NotificationRepository, ctx context.Context, tenant, delivery shared.ID) {
	t.Helper()
	d, err := repo.GetDelivery(ctx, tenant, delivery)
	if err != nil {
		t.Fatalf("get delivery: %v", err)
	}
	if d.State != notification.DeliveryPending {
		t.Fatalf("delivery = %+v, want left pending", d)
	}
}

func TestNotificationChannelChangeCancelsPendingDeliveries(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("notify-cancel")
	if _, err := pool.Exec(context.Background(), "INSERT INTO tenants(id,name) VALUES($1,$1)", tenant); err != nil {
		t.Fatal(err)
	}

	t.Run("disabling the channel cancels its pending delivery", func(t *testing.T) {
		repo, ctx, channel, delivery, now := newCancellationFixture(t, pool, tenant, "disable")
		channel.Enabled, channel.Revision, channel.UpdatedAt = false, 2, now.Add(time.Second)
		if _, err := repo.UpdateChannel(ctx, channel, "", false); err != nil {
			t.Fatalf("disable channel: %v", err)
		}
		assertCancelled(t, repo, ctx, tenant, delivery, "channel_disabled")
	})

	t.Run("deleting the channel cancels its pending delivery", func(t *testing.T) {
		repo, ctx, channel, delivery, now := newCancellationFixture(t, pool, tenant, "delete")
		if err := repo.DeleteChannel(ctx, tenant, channel.ID, channel.Revision, now.Add(time.Second)); err != nil {
			t.Fatalf("delete channel: %v", err)
		}
		assertCancelled(t, repo, ctx, tenant, delivery, "channel_deleted")
	})

	t.Run("changing the destination cancels the pending delivery", func(t *testing.T) {
		repo, ctx, channel, delivery, now := newCancellationFixture(t, pool, tenant, "destination")
		channel.Destination, channel.Revision, channel.UpdatedAt = "https://example.test/moved", 2, now.Add(time.Second)
		// replace=false: only the destination moves, the sealed secret is untouched.
		if _, err := repo.UpdateChannel(ctx, channel, "", false); err != nil {
			t.Fatalf("move destination: %v", err)
		}
		assertCancelled(t, repo, ctx, tenant, delivery, "destination_changed")
	})

	t.Run("rotating the secret cancels the pending delivery even at the same destination", func(t *testing.T) {
		repo, ctx, channel, delivery, now := newCancellationFixture(t, pool, tenant, "rotate")
		channel.Revision, channel.UpdatedAt = 2, now.Add(time.Second)
		// replace=true, destination unchanged: work.Sealed would otherwise still open under the
		// retired secret_version at send time.
		updated, err := repo.UpdateChannel(ctx, channel, "sealed-v2", true)
		if err != nil {
			t.Fatalf("rotate secret: %v", err)
		}
		if updated.SecretVersion != 2 {
			t.Fatalf("secret version = %d, want 2", updated.SecretVersion)
		}
		assertCancelled(t, repo, ctx, tenant, delivery, "destination_changed")
	})

	t.Run("a metadata-only edit leaves the pending delivery alone", func(t *testing.T) {
		repo, ctx, channel, delivery, now := newCancellationFixture(t, pool, tenant, "rename")
		channel.Name, channel.Revision, channel.UpdatedAt = "renamed", 2, now.Add(time.Second)
		if _, err := repo.UpdateChannel(ctx, channel, "", false); err != nil {
			t.Fatalf("rename channel: %v", err)
		}
		assertStillPending(t, repo, ctx, tenant, delivery)
	})

	t.Run("disabling while also rotating cancels once, with channel_disabled", func(t *testing.T) {
		repo, ctx, channel, delivery, now := newCancellationFixture(t, pool, tenant, "both")
		channel.Enabled, channel.Revision, channel.UpdatedAt = false, 2, now.Add(time.Second)
		if _, err := repo.UpdateChannel(ctx, channel, "sealed-v2", true); err != nil {
			t.Fatalf("disable and rotate: %v", err)
		}
		assertCancelled(t, repo, ctx, tenant, delivery, "channel_disabled")
	})

	t.Run("a delivery with a started attempt is left for FinishAttempt to close out", func(t *testing.T) {
		repo, ctx, channel, delivery, now := newCancellationFixture(t, pool, tenant, "started")
		startAttempt(t, pool, tenant, delivery, now)
		channel.Enabled, channel.Revision, channel.UpdatedAt = false, 2, now.Add(time.Second)
		if _, err := repo.UpdateChannel(ctx, channel, "", false); err != nil {
			t.Fatalf("disable channel: %v", err)
		}
		assertStillPending(t, repo, ctx, tenant, delivery)
	})
}
