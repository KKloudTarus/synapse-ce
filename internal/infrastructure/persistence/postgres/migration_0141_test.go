package postgres

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0141CorrelationEventTimeState(t *testing.T) {
	isolated := newIsolatedMigrationDB(t, 141, 140)
	db := isolated.db
	if err := goose.UpTo(db, ".", 141); err != nil {
		t.Fatalf("apply 0141: %v", err)
	}

	for _, table := range []string{"correlation_checkpoints", "correlation_staged_signals", "correlation_assignments", "correlation_active_sessions"} {
		requireMigrationTable(t, db, table, true)
		requireMigrationRLS(t, db, table)
	}
	requireMigrationIndexes(t, db, "idx_correlation_staged_signals_consume", "idx_correlation_assignments_incident", "idx_correlation_active_sessions_match")

	const tenant = "migration-0141-tenant"
	const engagement = "migration-0141-engagement"
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		if _, err := tx.Exec(`INSERT INTO engagements(id,tenant_id,name) VALUES($1,$2,$1)`, engagement, tenant); err != nil {
			t.Fatalf("seed engagement: %v", err)
		}
		requireMigrationWriteRejected(t, tx, `INSERT INTO correlation_checkpoints(tenant_id,engagement_id,max_observed_at,watermark)
			VALUES($1,$2,now(),now()+interval '1 second')`, tenant, engagement)
		if _, err := tx.Exec(`INSERT INTO correlation_checkpoints(tenant_id,engagement_id) VALUES($1,$2)`, tenant, engagement); err != nil {
			t.Fatalf("insert checkpoint: %v", err)
		}
		if _, err := tx.Exec(`INSERT INTO correlation_assignments(tenant_id,engagement_id,signal_id,incident_id,asset_id,occurred_at,outcome)
			VALUES($1,$2,'signal-1','incident-1','asset-1',now(),'attached')`, tenant, engagement); err != nil {
			t.Fatalf("insert immutable assignment: %v", err)
		}
		requireMigrationWriteRejected(t, tx, `UPDATE correlation_assignments SET incident_id='forged' WHERE tenant_id=$1 AND engagement_id=$2 AND signal_id='signal-1'`, tenant, engagement)
	})

	if err := goose.DownTo(db, ".", 140); err != nil {
		t.Fatalf("roll back 0141: %v", err)
	}
	requireMigrationTable(t, db, "correlation_checkpoints", false)
	if err := goose.UpTo(db, ".", 141); err != nil {
		t.Fatalf("reapply 0141: %v", err)
	}
	requireMigrationTable(t, db, "correlation_checkpoints", true)
}
