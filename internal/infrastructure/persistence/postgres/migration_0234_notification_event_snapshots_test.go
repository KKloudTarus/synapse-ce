package postgres

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0234SnapshotGuardsAndRollback(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 234, 229)
	db := isolate.db
	if err := goose.UpTo(db, ".", 234); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES('snapshot-migration','Snapshots')`); err != nil {
		t.Fatal(err)
	}
	withTenant := func(fn func(*sql.Tx) error) error {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`SELECT set_config('app.current_tenant','snapshot-migration',true)`); err != nil {
			return err
		}
		if err := fn(tx); err != nil {
			return err
		}
		return tx.Commit()
	}
	if err := withTenant(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO notification_source_records
			(tenant_id,source_kind,source_id,event_type,occurred_at,data,context,capture_version)
			VALUES('snapshot-migration','finding_created','finding','finding.created',now(),'{"finding_id":"finding"}','{"vars":{"finding_title":"Original"}}',3)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`UPDATE notification_source_records SET data='{}' WHERE tenant_id='snapshot-migration'`,
		`UPDATE notification_source_records SET context='{}' WHERE tenant_id='snapshot-migration'`,
		`UPDATE notification_source_records SET capture_version=1 WHERE tenant_id='snapshot-migration'`,
		`UPDATE notification_source_records SET processed_at=now() WHERE tenant_id='snapshot-migration'`,
	} {
		if err := withTenant(func(tx *sql.Tx) error { _, err := tx.Exec(query); return err }); err == nil {
			t.Fatalf("guard accepted %s", query)
		}
	}
	if err := goose.DownTo(db, ".", 229); err == nil || !strings.Contains(err.Error(), "drain snapshot captures") {
		t.Fatalf("pending intent rollback=%v", err)
	}
	if err := withTenant(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`SELECT set_config('synapse.notification_source_capability','snapshot-v1',true)`); err != nil {
			return err
		}
		_, err := tx.Exec(`UPDATE notification_source_records SET processed_at=now() WHERE tenant_id='snapshot-migration'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 229); err != nil {
		t.Fatalf("rollback consumed snapshot: %v", err)
	}
	if err := goose.UpTo(db, ".", 234); err != nil {
		t.Fatalf("reapply populated migration: %v", err)
	}
	if err := withTenant(func(tx *sql.Tx) error {
		var format int
		var title string
		err := tx.QueryRow(`SELECT capture_version,context->'vars'->>'finding_title'
			FROM notification_source_records WHERE tenant_id='snapshot-migration' AND source_id='finding'`).Scan(&format, &title)
		if err == nil && (format != 1 || title != "Original") {
			t.Fatalf("rollback/reapply changed retained facts: %d %q", format, title)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
