package postgres

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0143ResponseHaltWriterPolicy(t *testing.T) {
	isolated := newIsolatedMigrationDB(t, 143, 142)
	db := isolated.db
	if err := goose.UpTo(db, ".", 143); err != nil {
		t.Fatalf("apply 0143: %v", err)
	}

	requireMigrationRLS(t, db, "response_halt_fences")
	requireMigrationPolicies(t, db, "response_halt_fences", "response_halt_fences_tenant_insert", "response_halt_fences_tenant_select", "response_halt_fences_tenant_update")

	const tenant = "migration-0143-tenant"
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		if _, err := tx.Exec(`INSERT INTO response_halt_fences(tenant_id,generation,halted) VALUES($1,1,true)`, tenant); err != nil {
			t.Fatalf("insert halt fence: %v", err)
		}
		requireMigrationWriteRejected(t, tx, `UPDATE response_halt_fences SET generation=0 WHERE tenant_id=$1`, tenant)
	})

	if err := goose.DownTo(db, ".", 142); err != nil {
		t.Fatalf("roll back 0143: %v", err)
	}
	requireMigrationPolicies(t, db, "response_halt_fences", "response_halt_fences_tenant_isolation")
	if err := goose.UpTo(db, ".", 143); err != nil {
		t.Fatalf("reapply 0143: %v", err)
	}
	requireMigrationPolicies(t, db, "response_halt_fences", "response_halt_fences_tenant_insert", "response_halt_fences_tenant_select", "response_halt_fences_tenant_update")
}
