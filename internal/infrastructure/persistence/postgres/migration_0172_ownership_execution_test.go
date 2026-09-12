package postgres

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0171And0172OwnershipExecutionUpgrade(t *testing.T) {
	_, db := ownershipTestDatabase(t, 166, func(db *sql.DB) {
		if _, err := db.Exec(`BEGIN; SELECT set_config('app.current_tenant','default',true); INSERT INTO engagements(tenant_id,id,name) VALUES('default','before-capture','Before capture'); INSERT INTO findings(tenant_id,engagement_id,id,title,assignee) VALUES('default','before-capture','historical','Existing finding','Existing owner'); COMMIT`); err != nil {
			t.Fatal(err)
		}
	})
	tables := []string{"ownership_sources", "ownership_source_snapshots", "ownership_source_readiness", "ownership_finding_sources", "ownership_dirty_findings", "ownership_dirty_scopes", "ownership_work_items", "ownership_run_requests"}
	for _, table := range tables {
		requireMigrationRLS(t, db, table)
	}
	var count int
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant','default',true)`); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(`SELECT count(*) FROM ownership_dirty_findings`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("migration enqueued history: %d %v", count, err)
	}
	var assignee string
	if err := tx.QueryRow(`SELECT assignee FROM findings WHERE id='historical'`).Scan(&assignee); err != nil || assignee != "Existing owner" {
		t.Fatalf("legacy data changed: %s %v", assignee, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 166); err != nil {
		t.Fatal(err)
	}
	for _, table := range tables {
		requireMigrationTable(t, db, table, false)
	}
	if err := goose.UpTo(db, ".", 168); err != nil {
		t.Fatal(err)
	}
	for _, table := range tables {
		requireMigrationRLS(t, db, table)
	}
}
