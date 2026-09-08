package postgres

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0141IncidentResponseProvenance(t *testing.T) {
	isolated := newIsolatedMigrationDB(t, 141, 140)
	db := isolated.db
	if err := goose.UpTo(db, ".", 141); err != nil {
		t.Fatalf("apply 0141: %v", err)
	}

	for _, table := range []string{"incident_response_links", "incident_merge_edges"} {
		requireMigrationTable(t, db, table, true)
		requireMigrationRLS(t, db, table)
	}
	requireMigrationIndexes(t, db, "endpoint_timeline_source_idx", "idx_incident_response_links_pending", "idx_incident_merge_edges_target")

	const tenant = "migration-0141-tenant"
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		if _, err := tx.Exec(`INSERT INTO incident_events(tenant_id,incident_id,seq,kind,occurred_at,actor,payload)
			VALUES($1,'incident-1',1,'created',now(),'correlator','{}'::jsonb)`, tenant); err != nil {
			t.Fatalf("seed incident event: %v", err)
		}
		requireMigrationWriteRejected(t, tx, `INSERT INTO incident_merge_edges(tenant_id,source_incident_id,canonical_incident_id,bridge_key,source_event_seq,actor,merged_at)
			VALUES($1,'incident-1','incident-1','bridge',1,'correlator',now())`, tenant)
		if _, err := tx.Exec(`INSERT INTO incident_merge_edges(tenant_id,source_incident_id,canonical_incident_id,bridge_key,source_event_seq,actor,merged_at)
			VALUES($1,'incident-1','incident-2','bridge',1,'correlator',now())`, tenant); err != nil {
			t.Fatalf("insert immutable merge edge: %v", err)
		}
		requireMigrationWriteRejected(t, tx, `DELETE FROM incident_merge_edges WHERE tenant_id=$1 AND source_incident_id='incident-1'`, tenant)
	})

	if err := goose.DownTo(db, ".", 140); err != nil {
		t.Fatalf("roll back 0141: %v", err)
	}
	requireMigrationTable(t, db, "incident_merge_edges", false)
	var sourceColumn bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='endpoint_timeline' AND column_name='source_agent_id')`).Scan(&sourceColumn); err != nil {
		t.Fatalf("inspect endpoint source column: %v", err)
	}
	if sourceColumn {
		t.Fatal("rollback 0141 retained endpoint source provenance column")
	}
	if err := goose.UpTo(db, ".", 141); err != nil {
		t.Fatalf("reapply 0141: %v", err)
	}
	requireMigrationTable(t, db, "incident_merge_edges", true)
}
