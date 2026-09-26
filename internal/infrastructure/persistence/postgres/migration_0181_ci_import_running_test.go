package postgres

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0181CIImportsPreserveServerScanSlotAndRollback(t *testing.T) {
	isolated := newIsolatedMigrationDB(t, 181, 180)
	db := isolated.db
	const tenant = "ci-index-tenant"
	const engagement = "ci-index-engagement"
	if _, err := db.Exec("INSERT INTO tenants(id,name) VALUES($1,'CI index test')", tenant); err != nil {
		t.Fatal(err)
	}
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec("INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,'CI index')", engagement, tenant); err != nil {
			t.Fatal(err)
		}
	})
	insert := func(id, kind string) error {
		_, err := db.Exec(`INSERT INTO scan_jobs(id,engagement_id,target,kind,status,stage,progress,started_at,debug_events)
			VALUES($1,$2,'target',$3,'running','importing',1,now(),'[]'::jsonb)`, id, engagement, kind)
		return err
	}
	if err := insert("ci-index-server", "git"); err != nil {
		t.Fatalf("insert initial running server scan: %v", err)
	}
	if err := insert("ci-index-before", "ci-import"); err == nil {
		t.Fatal("pre-migration index unexpectedly allowed an overlapping CI import")
	}
	if err := goose.UpTo(db, ".", 181); err != nil {
		t.Fatalf("apply CI running-index migration: %v", err)
	}
	for _, id := range []string{"ci-index-a", "ci-index-b"} {
		if err := insert(id, "ci-import"); err != nil {
			t.Fatalf("post-migration concurrent CI import %s: %v", id, err)
		}
	}
	if err := insert("ci-index-second-server", "git"); err == nil {
		t.Fatal("post-migration index allowed two concurrent server scans")
	}
	if err := goose.DownTo(db, ".", 180); err != nil {
		t.Fatalf("roll back CI running-index migration: %v", err)
	}
	var failed int
	if err := db.QueryRow(`SELECT count(*) FROM scan_jobs
		WHERE engagement_id=$1 AND kind='ci-import' AND status='failed'
			AND stage='migration-rollback' AND finished_at IS NOT NULL`, engagement).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if failed != 2 {
		t.Fatalf("rollback failed %d concurrent CI imports, want two", failed)
	}
	if err := insert("ci-index-after-rollback", "ci-import"); err == nil {
		t.Fatal("rollback did not restore the original one-running-job index")
	}
}
