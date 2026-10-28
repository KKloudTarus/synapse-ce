package postgres

import (
	"database/sql"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
)

func TestMigration0266BackfillsRetiredDocumentRemovalKind(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 266, 265)
	const tenant = "migration-0266"
	seedDocumentRemoteRevisionLegacyRows(t, isolate.db, tenant)
	withMigrationTenant(t, isolate.db, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`UPDATE document_links SET retired_at=$1 WHERE tenant_id=$2`, time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC), tenant); err != nil {
			t.Fatalf("retire legacy document link: %v", err)
		}
	})
	if err := goose.UpTo(isolate.db, ".", 266); err != nil {
		t.Fatalf("upgrade managed document snapshots: %v", err)
	}
	withMigrationTenant(t, isolate.db, tenant, func(tx *sql.Tx) {
		var kind, profile string
		if err := tx.QueryRow(`SELECT removal_kind,access_profile FROM document_links WHERE tenant_id=$1`, tenant).Scan(&kind, &profile); err != nil {
			t.Fatalf("read upgraded document link: %v", err)
		}
		if kind != "purge" || profile != "" {
			t.Fatalf("upgraded removal/profile=(%q,%q), want (purge,empty)", kind, profile)
		}
	})
	if err := goose.DownTo(isolate.db, ".", 265); err != nil {
		t.Fatalf("roll back legacy purge retirement: %v", err)
	}
	if err := goose.UpTo(isolate.db, ".", 266); err != nil {
		t.Fatalf("reapply managed document snapshots: %v", err)
	}
	withMigrationTenant(t, isolate.db, tenant, func(tx *sql.Tx) {
		var kind, profile string
		if err := tx.QueryRow(`SELECT removal_kind,access_profile FROM document_links WHERE tenant_id=$1`, tenant).Scan(&kind, &profile); err != nil {
			t.Fatalf("read reapplied document link: %v", err)
		}
		if kind != "purge" || profile != "" {
			t.Fatalf("reapplied removal/profile=(%q,%q), want (purge,empty)", kind, profile)
		}
	})
}
