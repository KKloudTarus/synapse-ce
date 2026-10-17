package postgres

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0239DigestSchemaAndRollbackGuard(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 239, 238)
	db := isolate.db
	if err := goose.UpTo(db, ".", 239); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES('digest-migration','Digests')`); err != nil {
		t.Fatal(err)
	}
	var eventIndex string
	if err := db.QueryRow(`SELECT indexdef FROM pg_indexes WHERE schemaname='public' AND indexname='notification_digest_windows_event'`).Scan(&eventIndex); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(eventIndex, "UNIQUE INDEX") || !strings.Contains(eventIndex, "WHERE (event_id IS NOT NULL)") {
		t.Fatalf("event lookup index=%q, want partial unique index", eventIndex)
	}
	withTenant := func(fn func(*sql.Tx) error) error {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`SELECT set_config('app.current_tenant','digest-migration',true)`); err != nil {
			return err
		}
		if err := fn(tx); err != nil {
			return err
		}
		return tx.Commit()
	}
	if err := withTenant(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO notification_events(tenant_id,id,event_type,source_kind,source_id,schema_version,occurred_at,data,test_template)
			VALUES('digest-migration','template-test','notification.test','template_test','template-test',1,now(),'{}',
			'{"tenant_id":"digest-migration","template_id":"template","version":1,"fields":{"body":"x"},"checksum":"sum","created_at":"2026-01-01T00:00:00Z","created_by":"admin"}')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := withTenant(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE notification_events SET test_template='{}' WHERE tenant_id='digest-migration' AND id='template-test'`)
		return err
	}); err == nil {
		t.Fatal("test template update bypassed immutable notification event guard")
	}
	if err := goose.DownTo(db, ".", 238); err == nil || !strings.Contains(err.Error(), "drain notification digests") {
		t.Fatalf("rollback with a pinned test template = %v, want refusal", err)
	}
}
