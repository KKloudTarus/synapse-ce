package postgres

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0270PreservesAuthorityOnRollback(t *testing.T) {
	isolated := newIsolatedMigrationDB(t, 270, 269)
	db := isolated.db
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES('dast-migration','DAST')`); err != nil {
		t.Fatal(err)
	}
	withMigrationTenant(t, db, "dast-migration", func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO engagements(id,tenant_id,name) VALUES('migration-dast-eng','dast-migration','DAST')`); err != nil {
			t.Fatal(err)
		}
	})
	withMigrationTenant(t, db, "dast-migration", func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO agent_approvals (action_id,tenant_id,session_id,engagement_id,tool,action,risk,proposed_at,decision_state) VALUES ('migration-dast-action','dast-migration','session','migration-dast-eng','tool','action','intrusive',now(),'consumed')`); err != nil {
			t.Fatal(err)
		}
	})
	if err := goose.UpTo(db, ".", 270); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 269); err != nil {
		t.Fatalf("legacy data rollback: %v", err)
	}
	if err := goose.UpTo(db, ".", 270); err != nil {
		t.Fatal(err)
	}
	withMigrationTenant(t, db, "dast-migration", func(tx *sql.Tx) {
		if _, err := tx.Exec(`UPDATE agent_approvals SET consumed_by_dast_run_id='owned-run' WHERE action_id='migration-dast-action'`); err != nil {
			t.Fatal(err)
		}
	})
	if err := goose.DownTo(db, ".", 269); err == nil || !strings.Contains(err.Error(), "cannot drop DAST grant authority") {
		t.Fatalf("owned rollback: %v", err)
	}
	withMigrationTenant(t, db, "dast-migration", func(tx *sql.Tx) {
		requireMigrationWriteRejected(t, tx, `UPDATE agent_approvals SET decision_state='approved' WHERE action_id='migration-dast-action'`)
	})
	withMigrationTenant(t, db, "dast-migration", func(tx *sql.Tx) {
		if _, err := tx.Exec(`UPDATE agent_approvals SET consumed_by_dast_run_id=NULL WHERE action_id='migration-dast-action'`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO dast_runs(tenant_id,id,engagement_id,action_id,actor,status,started_at,egress_grant_issued_at) VALUES('dast-migration','migration-dast-run','migration-dast-eng','migration-dast-action','operator','running',now(),now())`); err != nil {
			t.Fatal(err)
		}
	})
	if err := goose.DownTo(db, ".", 269); err == nil || !strings.Contains(err.Error(), "cannot drop DAST grant authority") {
		t.Fatalf("issued rollback: %v", err)
	}
}
