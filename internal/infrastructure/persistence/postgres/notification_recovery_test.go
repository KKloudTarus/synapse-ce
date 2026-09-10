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
)

func TestNotificationPostgresRecoveryAndAuditOutage(t *testing.T) {
	pool := notificationTestPool(t)
	tenant := shared.ID("recovery")
	ctx := shared.WithTenant(context.Background(), tenant)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('recovery','Recovery')`); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error { _, err := tx.Exec(ctx, q, args...); return err }); err != nil {
			t.Fatal(err)
		}
	}
	repo := NewNotificationRepository(pool)
	channel := notification.Channel{TenantID: tenant, ID: "channel", Name: "Hook", Type: notification.ChannelWebhook, Enabled: true, Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now}
	if _, err := repo.CreateChannel(ctx, channel, "sealed"); err != nil {
		t.Fatal(err)
	}
	publish := func(source string) shared.ID {
		t.Helper()
		id, err := repo.PublishToChannel(ctx, notification.Event{TenantID: tenant, ID: shared.ID(source), Type: notification.EventTest, SourceKind: "test", SourceID: source, SchemaVersion: 1, OccurredAt: now, Data: json.RawMessage(`{"title":"test"}`)}, channel.ID)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	queue := NewJobQueue(pool, &notificationTestIDs{})
	did := publish("crash")
	old, err := queue.Claim(ctx, time.Minute, "notification.deliver")
	if err != nil || old == nil {
		t.Fatalf("claim: %v", err)
	}
	if _, err = repo.BeginAttempt(ctx, tenant, did, old.ID, old.Fence, "unknown", now); err != nil {
		t.Fatal(err)
	}
	// Simulate process loss after the receiver may have acknowledged the request.
	exec(`UPDATE jobs SET claimed_until=now()-interval '1 second' WHERE id=$1`, old.ID)
	reclaimed, err := queue.Claim(ctx, time.Minute, "notification.deliver")
	if err != nil || reclaimed == nil {
		t.Fatalf("reclaim: %v", err)
	}
	if err = repo.FinishAttempt(ctx, tenant, did, old.ID, old.Fence, "unknown", now, "delivered", 204, "", nil); !errors.Is(err, ports.ErrStaleLease) {
		t.Fatalf("stale finish: %v", err)
	}
	if _, err = repo.BeginAttempt(ctx, tenant, did, reclaimed.ID, reclaimed.Fence, "known", now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = repo.FinishAttempt(ctx, tenant, did, reclaimed.ID, reclaimed.Fence, "known", now.Add(2*time.Second), "delivered", 204, "", nil); err != nil {
		t.Fatal(err)
	}
	if err = queue.Complete(ctx, reclaimed.ID, reclaimed.Fence); err != nil {
		t.Fatal(err)
	}
	attempts, err := repo.ListAttempts(ctx, tenant, did)
	if err != nil || len(attempts) != 2 || attempts[0].Outcome != "started" || attempts[1].Outcome != "delivered" {
		t.Fatalf("unknown history: %+v %v", attempts, err)
	}
	// Audit outage does not revert the success or send again. Intent is retried later.
	exec(`CREATE FUNCTION notification_test_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected audit outage'; END $$`)
	exec(`CREATE TRIGGER notification_test_audit_failure BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION notification_test_audit_failure()`)
	reconcile := func() {
		t.Helper()
		if err := WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error { return repo.reconcileTx(ctx, tx, tenant) }); err != nil {
			t.Fatal(err)
		}
	}
	reconcile()
	var pending int
	if err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM notification_audit_intents WHERE recorded_at IS NULL`).Scan(&pending)
	}); err != nil || pending != 1 {
		t.Fatalf("audit intent lost: %d %v", pending, err)
	}
	exec(`DROP TRIGGER notification_test_audit_failure ON audit_log`)
	reconcile()
	if err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM notification_audit_intents WHERE recorded_at IS NULL`).Scan(&pending)
	}); err != nil || pending != 0 {
		t.Fatalf("audit recovery: %d %v", pending, err)
	}
	// A crash between durable queue failure and its best-effort callback is repaired.
	dead := publish("dead")
	job, err := queue.Claim(ctx, time.Minute, "notification.deliver")
	if err != nil || job == nil {
		t.Fatalf("dead claim: %v", err)
	}
	if err = queue.Deadletter(ctx, job.ID, job.Fence); err != nil {
		t.Fatal(err)
	}
	reconcile()
	delivery, err := repo.GetDelivery(ctx, tenant, dead)
	if err != nil || delivery.State != notification.DeliveryDead {
		t.Fatalf("dead repair: %+v %v", delivery, err)
	}
	// An old hook cannot cancel pending work that the queue has not dead-lettered.
	pendingID := publish("pending")
	if err = repo.DeadLetterDelivery(ctx, tenant, pendingID, "worker_dead_letter"); err != nil {
		t.Fatal(err)
	}
	delivery, err = repo.GetDelivery(ctx, tenant, pendingID)
	if err != nil || delivery.State != notification.DeliveryPending {
		t.Fatalf("unfenced hook: %+v %v", delivery, err)
	}
	channel.Enabled = false
	channel.Revision++
	channel.UpdatedAt = now.Add(3 * time.Second)
	if _, err = repo.UpdateChannel(ctx, channel, "", false); err != nil {
		t.Fatal(err)
	}
	delivery, err = repo.GetDelivery(ctx, tenant, pendingID)
	if err != nil || delivery.State != notification.DeliveryCancelled {
		t.Fatalf("disable: %+v %v", delivery, err)
	}
	// Finalized history cannot be rewritten, even by the table owner under tenant RLS.
	for _, q := range []string{`UPDATE notification_delivery_attempts SET outcome='failed' WHERE id='known'`, `UPDATE notification_events SET data='{}' WHERE id='crash'`, `UPDATE notification_channel_versions SET sealed_config='replacement'`} {
		if err = WithTenant(ctx, pool, tenant.String(), func(tx pgx.Tx) error { _, err := tx.Exec(ctx, q); return err }); err == nil {
			t.Fatalf("mutable history: %s", q)
		}
	}
}
