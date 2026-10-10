package postgres

import (
	"context"
	"database/sql"
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

func TestNotificationRuntimeGuardRollbackRequiresWebhookDrain(t *testing.T) {
	isolation := newIsolatedMigrationDB(t, 226, 225)
	db := isolation.db
	if err := goose.UpTo(db, ".", 226); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES('runtime-guard','Runtime guard')`); err != nil {
		t.Fatal(err)
	}
	if err := withMigrationTenantErr(db, "runtime-guard", func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO notification_channels(tenant_id,id,name,channel_type,enabled,created_at,updated_at)
			VALUES('runtime-guard','runtime-hook','Runtime hook','webhook',true,now(),now())`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 225); err == nil {
		t.Fatal("runtime guard rollback accepted an enabled webhook channel")
	}
	if err := withMigrationTenantErr(db, "runtime-guard", func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE notification_channels SET enabled=false WHERE tenant_id='runtime-guard' AND id='runtime-hook'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 225); err != nil {
		t.Fatalf("runtime guard rollback after drain: %v", err)
	}
}

func TestNotificationRuntimeGuardRollbackSeesWebhookEnabledDuringMaintenanceWait(t *testing.T) {
	isolation := newIsolatedMigrationDB(t, 226, 225)
	db := isolation.db
	if err := goose.UpTo(db, ".", 226); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES('runtime-guard-race','Runtime guard race')`); err != nil {
		t.Fatal(err)
	}
	if err := withMigrationTenantErr(db, "runtime-guard-race", func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO notification_channels(tenant_id,id,name,channel_type,enabled,created_at,updated_at)
			VALUES('runtime-guard-race','held-hook','Held hook','webhook',false,now(),now())`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	writer, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Rollback() }()
	if _, err := writer.Exec(`SELECT set_config('app.current_tenant','runtime-guard-race',true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(`UPDATE notification_channels SET enabled=true WHERE tenant_id='runtime-guard-race' AND id='held-hook'`); err != nil {
		t.Fatal(err)
	}
	down := make(chan error, 1)
	go func() { down <- goose.DownTo(db, ".", 225) }()
	waitForNotificationRuntimeGuardLockWait(t, db, "notification_channels")
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-down:
		if err == nil {
			t.Fatal("rollback missed a webhook channel enabled while it waited")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("rollback did not finish after maintenance writer released")
	}
	assertNotificationRuntimeGuardRollbackRefused(t, db)
}

func TestNotificationRuntimeGuardRollbackSeesNewTenantWebhookDuringMaintenanceWait(t *testing.T) {
	isolation := newIsolatedMigrationDB(t, 226, 225)
	db := isolation.db
	if err := goose.UpTo(db, ".", 226); err != nil {
		t.Fatal(err)
	}
	writer, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Rollback() }()
	if _, err := writer.Exec(`INSERT INTO tenants(id,name) VALUES('runtime-guard-new-tenant','Runtime guard new tenant')`); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(`SELECT set_config('app.current_tenant','runtime-guard-new-tenant',true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(`INSERT INTO notification_channels(tenant_id,id,name,channel_type,enabled,created_at,updated_at)
		VALUES('runtime-guard-new-tenant','new-tenant-hook','New tenant hook','webhook',true,now(),now())`); err != nil {
		t.Fatal(err)
	}
	down := make(chan error, 1)
	go func() { down <- goose.DownTo(db, ".", 225) }()
	waitForNotificationRuntimeGuardLockWait(t, db, "tenants")
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-down:
		if err == nil {
			t.Fatal("rollback missed a new tenant webhook enabled while it waited")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("rollback did not finish after new tenant writer released")
	}
	assertNotificationRuntimeGuardRollbackRefused(t, db)
}

func TestNotificationRuntimeGuardRollbackFencesWebhookChangeThroughGuardRemoval(t *testing.T) {
	isolation := newIsolatedMigrationDB(t, 226, 225)
	db := isolation.db
	if err := goose.UpTo(db, ".", 226); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES('runtime-guard-fence','Runtime guard fence')`); err != nil {
		t.Fatal(err)
	}
	if err := withMigrationTenantErr(db, "runtime-guard-fence", func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO notification_channels(tenant_id,id,name,channel_type,enabled,created_at,updated_at)
			VALUES('runtime-guard-fence','fenced-hook','Fenced hook','webhook',false,now(),now())`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	blocker, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback() }()
	if _, err := blocker.Exec(`LOCK TABLE notification_delivery_attempts IN ACCESS SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	down := make(chan error, 1)
	go func() { down <- goose.DownTo(db, ".", 225) }()
	waitForNotificationRuntimeGuardRelationLock(t, db, "notification_delivery_attempts", "AccessExclusiveLock", false)
	writerDone := make(chan error, 1)
	go func() {
		writerDone <- withMigrationTenantErr(db, "runtime-guard-fence", func(tx *sql.Tx) error {
			_, err := tx.Exec(`UPDATE notification_channels SET enabled=true WHERE tenant_id='runtime-guard-fence' AND id='fenced-hook'`)
			return err
		})
	}()
	waitForNotificationRuntimeGuardRelationLock(t, db, "notification_channels", "RowExclusiveLock", false)
	if err := blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-down:
		if err != nil {
			t.Fatalf("rollback after fenced mutation: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("rollback did not complete after the drop blocker released")
	}
	select {
	case err := <-writerDone:
		if err != nil {
			t.Fatalf("queued webhook mutation after rollback: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("queued webhook mutation did not resume after rollback")
	}
}
func TestNotificationRuntimeGuardRollbackLockTimeoutRetainsGuard(t *testing.T) {
	isolation := newIsolatedMigrationDB(t, 226, 225)
	db := isolation.db
	if err := goose.UpTo(db, ".", 226); err != nil {
		t.Fatal(err)
	}
	blocker, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback() }()
	if _, err := blocker.Exec(`LOCK TABLE notification_delivery_attempts IN ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	down := make(chan error, 1)
	go func() { down <- goose.DownTo(db, ".", 225) }()
	waitForNotificationRuntimeGuardLockWait(t, db, "notification_delivery_attempts")
	select {
	case err := <-down:
		if err == nil {
			t.Fatal("rollback ignored the bounded maintenance lock wait")
		}
	case <-time.After(7 * time.Second):
		t.Fatal("rollback did not fail after the maintenance lock timeout")
	}
	assertNotificationRuntimeGuardRollbackRefused(t, db)
}

func TestNotificationRuntimeGuardRollbackRejectsUnsupportedIsolation(t *testing.T) {
	isolation := newIsolatedMigrationDB(t, 226, 225)
	db := isolation.db
	if err := goose.UpTo(db, ".", 226); err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL REPEATABLE READ`); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := db.Exec(`SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL READ COMMITTED`); err != nil {
			t.Errorf("reset migration test isolation: %v", err)
		}
	}()
	if err := goose.DownTo(db, ".", 225); err == nil {
		t.Fatal("rollback accepted a repeatable-read transaction")
	}
	assertNotificationRuntimeGuardRollbackRefused(t, db)
}
func waitForNotificationRuntimeGuardLockWait(t *testing.T, db *sql.DB, table string) {
	t.Helper()
	waitForNotificationRuntimeGuardRelationLock(t, db, table, "ShareRowExclusiveLock", false)
}

func waitForNotificationRuntimeGuardRelationLock(t *testing.T, db *sql.DB, table, mode string, granted bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	const query = `SELECT EXISTS (
		SELECT 1 FROM pg_locks
		WHERE relation = $1::regclass AND mode = $2 AND granted = $3
	)`
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var found bool
		if err := db.QueryRowContext(ctx, query, table, mode, granted).Scan(&found); err != nil {
			t.Fatalf("inspect notification runtime guard maintenance lock request: %v", err)
		}
		if found {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("rollback never requested %s on %s with granted=%t: %v", mode, table, granted, ctx.Err())
		case <-ticker.C:
		}
	}
}

func assertNotificationRuntimeGuardRollbackRefused(t *testing.T, db *sql.DB) {
	t.Helper()
	var guardExists bool
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='notification_webhook_attempt_guard')`).Scan(&guardExists); err != nil {
		t.Fatal(err)
	}
	if !guardExists {
		t.Fatal("failed rollback removed the webhook guard")
	}
	var version int64
	if err := db.QueryRow(`SELECT version_id FROM goose_db_version WHERE is_applied ORDER BY id DESC LIMIT 1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 226 {
		t.Fatalf("failed rollback applied version=%d, want 226", version)
	}
}
func withMigrationTenantErr(db *sql.DB, tenant string, fn func(*sql.Tx) error) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant',$1,true)`, tenant); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
