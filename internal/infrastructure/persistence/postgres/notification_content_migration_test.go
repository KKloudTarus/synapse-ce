package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"
)

func TestNotificationContentMigrationPreservesHistoryAndRefusesPendingDowngrade(t *testing.T) {
	isolated := newIsolatedMigrationDB(t, 224, 223)
	db := isolated.db
	if err := goose.UpTo(db, ".", 225); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES('capture-history','History')`); err != nil {
		t.Fatal(err)
	}
	exec := func(query string) error {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err = tx.Exec(`SELECT set_config('app.current_tenant','capture-history',true)`); err != nil {
			return err
		}
		if _, err = tx.Exec(query); err != nil {
			return err
		}
		return tx.Commit()
	}
	if err := exec(`INSERT INTO notification_source_records(tenant_id,source_kind,source_id,event_type,occurred_at,data,capture_version) VALUES('capture-history','scan_job','old','scan.completed',now(),'{"title":"Original"}',1),('capture-history','scan_job','new','scan.completed',now(),'{}',2)`); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 223); err == nil {
		t.Fatal("downgrade discarded a pending identity capture")
	}
	if err := exec(`SELECT set_config('synapse.notification_source_capability','identity-v1',true); UPDATE notification_source_records SET processed_at=now() WHERE source_id='new'`); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 223); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpTo(db, ".", 225); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant','capture-history',true)`); err != nil {
		t.Fatal(err)
	}
	var title string
	if err := tx.QueryRow(`SELECT data->>'title' FROM notification_source_records WHERE source_id='old'`).Scan(&title); err != nil || title != "Original" {
		t.Fatalf("legacy history title=%q err=%v", title, err)
	}
}

func TestNotificationCapturePolicyRuntimeReadOnlyAndRawRoundTrip(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	var mode string
	if err := f.runtime.QueryRow(ctx, `SELECT mode FROM notification_capture_policy WHERE singleton`).Scan(&mode); err != nil || mode != "legacy" {
		t.Fatalf("runtime mode=%q err=%v", mode, err)
	}
	for _, query := range []string{`UPDATE notification_capture_policy SET mode='identity'`, `DELETE FROM notification_capture_policy`, `INSERT INTO notification_capture_policy(singleton) VALUES(true)`} {
		if _, err := f.runtime.Exec(ctx, query); err == nil {
			t.Fatalf("runtime changed operator policy: %s", query)
		}
	}
	if _, err := f.admin.Exec(ctx, `INSERT INTO tenants(id,name) VALUES('raw-destination','Raw')`); err != nil {
		t.Fatal(err)
	}
	tenant := shared.ID("raw-destination")
	ctx = shared.WithTenant(ctx, tenant)
	repo := NewNotificationRepository(f.runtime)
	now := time.Now().UTC().Truncate(time.Microsecond)
	channel := notification.Channel{TenantID: tenant, ID: "raw-hook", Name: "Raw hook", Type: notification.ChannelWebhook, DataClass: notification.DataClassDetail, RawEvent: true, Enabled: true, Revision: 1, SecretVersion: 1, CreatedAt: now, UpdatedAt: now}
	if _, err := repo.CreateChannel(ctx, channel, "sealed"); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetChannel(ctx, tenant, channel.ID)
	if err != nil || !got.RawEvent {
		t.Fatalf("raw flag round-trip=%v err=%v", got.RawEvent, err)
	}
	if err := WithTenant(ctx, f.runtime, tenant.String(), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE notification_channels SET data_class='signal' WHERE id='raw-hook'`)
		return err
	}); err == nil {
		t.Fatal("database allowed raw mode below detail")
	}
	got.RawEvent = false
	got.DataClass = notification.DataClassSignal
	got.Revision = 2
	if _, err := repo.UpdateChannel(ctx, got, "sealed", false); err != nil {
		t.Fatal(err)
	}
	got, err = repo.GetChannel(ctx, tenant, channel.ID)
	if err != nil || got.RawEvent || got.Class() != notification.DataClassSignal {
		t.Fatalf("disabled raw flag round-trip=%v class=%v err=%v", got.RawEvent, got.Class(), err)
	}
}
