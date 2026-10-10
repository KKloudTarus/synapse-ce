package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// The base is 194, the last migration before this branch. 0196 does not depend on 0195 (the
// template store), so the channel health schema is checked on its own.
const migration0196Base = 194

func TestMigration0196NotificationChannelHealthSchema(t *testing.T) {
	_, db := ownershipTestDatabase(t, migration0196Base, nil)
	requireMigrationTable(t, db, "notification_channel_health_events", true)
	requireMigrationRLS(t, db, "notification_channel_health_events")
	requireMigrationIndexes(t, db, "notification_channel_health_events_channel")
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES('t-schema','Schema') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	// RLS is forced even for the owner, so each statement runs in its own tenant-bound transaction.
	exec := func(stmt string) error {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`SELECT set_config('app.current_tenant','t-schema',true)`); err != nil {
			return err
		}
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
		return tx.Commit()
	}
	if err := exec(`INSERT INTO notification_channels(tenant_id,id,name,channel_type,created_at,updated_at) VALUES('t-schema','c1','Hook','webhook',now(),now())`); err != nil {
		t.Fatal(err)
	}
	var failures int
	var code string
	var pausedAt *time.Time
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant','t-schema',true)`); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(`SELECT consecutive_permanent_failures,last_failure_code,paused_at FROM notification_channels WHERE id='c1'`).Scan(&failures, &code, &pausedAt); err != nil || failures != 0 || code != "" || pausedAt != nil {
		t.Fatalf("existing channels must start active with no failures: %d %q %v %v", failures, code, pausedAt, err)
	}
	_ = tx.Rollback()
	// Codes are bounded identifiers, so a URL or raw error text cannot be stored as health.
	for name, stmt := range map[string]string{
		"URL as failure code":        `UPDATE notification_channels SET last_failure_code='https://hooks.example/x?token=1' WHERE id='c1'`,
		"error text as pause reason": `UPDATE notification_channels SET paused_at=now(),paused_reason='Post "https://x": dial tcp' WHERE id='c1'`,
		"pause without reason":       `UPDATE notification_channels SET paused_at=now() WHERE id='c1'`,
		"reason without pause":       `UPDATE notification_channels SET paused_reason='consecutive_permanent_failures' WHERE id='c1'`,
		"negative count":             `UPDATE notification_channels SET consecutive_permanent_failures=-1 WHERE id='c1'`,
		"pause without its attempt":  `INSERT INTO notification_channel_health_events(tenant_id,id,channel_id,action,reason,actor,occurred_at) VALUES('t-schema','h0','c1','paused','consecutive_permanent_failures','system',now())`,
		"unknown action":             `INSERT INTO notification_channel_health_events(tenant_id,id,channel_id,action,actor,occurred_at) VALUES('t-schema','h0','c1','deleted','system',now())`,
		"URL in history code":        `INSERT INTO notification_channel_health_events(tenant_id,id,channel_id,action,failure_code,actor,occurred_at) VALUES('t-schema','h0','c1','resumed','https://x/y','admin',now())`,
		"history for no channel":     `INSERT INTO notification_channel_health_events(tenant_id,id,channel_id,action,actor,occurred_at) VALUES('t-schema','h0','missing','resumed','admin',now())`,
	} {
		if err := exec(stmt); err == nil {
			t.Errorf("%s: the schema accepted it", name)
		}
	}
	if err := exec(`UPDATE notification_channels SET paused_at=now(),paused_reason='consecutive_permanent_failures',consecutive_permanent_failures=5,last_failure_code='destination_blocked' WHERE id='c1'`); err != nil {
		t.Fatalf("valid pause: %v", err)
	}
	if err := exec(`INSERT INTO notification_channel_health_events(tenant_id,id,channel_id,action,reason,failure_code,failures,delivery_id,attempt_id,actor,occurred_at)
		VALUES('t-schema','h1','c1','paused','consecutive_permanent_failures','destination_blocked',5,'d1','a1','system',now())`); err != nil {
		t.Fatalf("valid pause row: %v", err)
	}
	// History is append-only even for the owner.
	if err := exec(`UPDATE notification_channel_health_events SET actor='someone' WHERE id='h1'`); err == nil {
		t.Error("health history row was updated")
	}
	if err := exec(`DELETE FROM notification_channel_health_events WHERE id='h1'`); err == nil {
		t.Error("health history row was deleted")
	}
	// Downgrading the runtime guards requires a disabled, drained webhook.
	if err := exec(`UPDATE notification_channels SET enabled=false WHERE id='c1'`); err != nil {
		t.Fatalf("disable fixture webhook before downgrade: %v", err)
	}
	if err := goose.DownTo(db, ".", migration0196Base); err != nil {
		t.Fatalf("migrate down: %v", err)
	}
	requireMigrationTable(t, db, "notification_channel_health_events", false)
	var columns int
	if err := db.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_name='notification_channels' AND column_name IN ('consecutive_permanent_failures','last_failure_code','last_failure_at','paused_at','paused_reason')`).Scan(&columns); err != nil || columns != 0 {
		t.Fatalf("down migration left %d health columns: %v", columns, err)
	}
}

// TestMigration0196ChannelHealthIsTenantIsolated is the hostile case under the runtime role, which
// does not bypass RLS: another tenant cannot read a channel's pause history, cannot forge history
// for it, cannot resume it and cannot clear its pause.
func TestMigration0196ChannelHealthIsTenantIsolated(t *testing.T) {
	pool, db := ownershipTestDatabase(t, migration0196Base, nil)
	for _, id := range []string{"t-a", "t-b"} {
		if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES($1,$1) ON CONFLICT DO NOTHING`, id); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	repo := NewNotificationRepository(pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	channel := notification.Channel{TenantID: "t-a", ID: "c1", Name: "Hook", Type: notification.ChannelWebhook, Enabled: true, Destination: "https://hooks.example/…", Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now}
	if _, err := repo.CreateChannel(ctx, channel, "sealed"); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		tr, err := repo.RecordChannelOutcome(ctx, "t-a", ports.NotificationChannelOutcome{ChannelID: "c1", DeliveryID: "d1", AttemptID: shared.ID("a" + string(rune('0'+i))), Class: notification.AttemptPermanent, Code: "http_404", At: now.Add(time.Duration(i) * time.Second), Threshold: 2})
		if err != nil {
			t.Fatal(err)
		}
		if tr.Paused != (i == 2) {
			t.Fatalf("outcome %d paused=%v", i, tr.Paused)
		}
	}

	// Tenant t-b sees nothing and changes nothing through the repository.
	if _, err := repo.ListChannelHealthEvents(ctx, "t-b", "c1", 10); err == nil {
		t.Fatal("tenant t-b listed tenant t-a's channel history")
	}
	if _, err := repo.ResumeChannel(ctx, "t-b", "c1", 1, "intruder", now); err == nil {
		t.Fatal("tenant t-b resumed tenant t-a's channel")
	}
	if tr, err := repo.RecordChannelOutcome(ctx, "t-b", ports.NotificationChannelOutcome{ChannelID: "c1", DeliveryID: "d9", AttemptID: "a9", Class: notification.AttemptPermanent, Code: "http_404", At: now, Threshold: 1}); err != nil || tr.Paused {
		t.Fatalf("tenant t-b recorded an outcome on tenant t-a's channel: %+v %v", tr, err)
	}
	// And directly under its own session.
	err := WithTenant(ctx, pool, "t-b", func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_channel_health_events`).Scan(&n); err != nil || n != 0 {
			t.Errorf("tenant t-b read %d history rows (%v)", n, err)
		}
		tag, err := tx.Exec(ctx, `UPDATE notification_channels SET paused_at=NULL,paused_reason=NULL WHERE tenant_id='t-a'`)
		if err != nil || tag.RowsAffected() != 0 {
			t.Errorf("tenant t-b cleared tenant t-a's pause: rows=%d err=%v", tag.RowsAffected(), err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = WithTenant(ctx, pool, "t-b", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO notification_channel_health_events(tenant_id,id,channel_id,action,actor,occurred_at) VALUES('t-a','forged','c1','resumed','intruder',now())`)
		return err
	})
	if err == nil {
		t.Fatal("tenant t-b forged history for tenant t-a")
	}
	// The runtime role cannot rewrite its own tenant's history either.
	err = WithTenant(ctx, pool, "t-a", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM notification_channel_health_events`)
		return err
	})
	if err == nil {
		t.Fatal("the runtime role deleted pause history")
	}

	got, err := repo.GetChannel(ctx, "t-a", "c1")
	if err != nil || !got.Health.Paused() || got.Health.ConsecutiveFailures != 2 {
		t.Fatalf("tenant t-a's channel changed under another tenant: %+v %v", got.Health, err)
	}
	history, err := repo.ListChannelHealthEvents(ctx, "t-a", "c1", 10)
	if err != nil || len(history) != 1 || history[0].AttemptID != "a2" {
		t.Fatalf("tenant t-a history = %+v, %v", history, err)
	}
}
