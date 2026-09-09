package postgres

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0139ResponseExecutionRuntime(t *testing.T) {
	isolated := newIsolatedMigrationDB(t, 139, 138)
	db := isolated.db
	if err := goose.UpTo(db, ".", 139); err != nil {
		t.Fatalf("apply 0139: %v", err)
	}

	for _, table := range []string{
		"response_audit_intents", "response_halt_dispatches", "response_verification_observations", "response_observer_bindings",
	} {
		requireMigrationTable(t, db, table, true)
		requireMigrationRLS(t, db, table)
	}
	requireMigrationPolicies(t, db, "response_audit_intents", "response_audit_intents_tenant_insert", "response_audit_intents_tenant_select", "response_audit_intents_tenant_update")
	requireMigrationPolicies(t, db, "response_halt_dispatches", "response_halt_dispatches_tenant_insert", "response_halt_dispatches_tenant_select")
	requireMigrationIndexes(t, db, "rai_pending_idx", "rhd_dispatch_idx", "idx_response_verification_action", "response_observer_bindings_asset_idx")

	// A clean runtime migration can return to 0138 and restore all its objects on reapply.
	if err := goose.DownTo(db, ".", 138); err != nil {
		t.Fatalf("roll back clean 0139: %v", err)
	}
	requireMigrationTable(t, db, "response_audit_intents", false)
	if err := goose.UpTo(db, ".", 139); err != nil {
		t.Fatalf("reapply 0139: %v", err)
	}

	const tenant = "migration-0139-tenant"
	withMigrationTenant(t, db, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		if _, err := tx.Exec(`INSERT INTO response_audit_intents(tenant_id,intent_id,actor,action,target,metadata,occurred_at)
			VALUES($1,'intent-1','operator','response.halt','host-1','{"idempotency_key":"intent-1"}'::jsonb,now())`, tenant); err != nil {
			t.Fatalf("insert audit intent: %v", err)
		}
		requireMigrationWriteRejected(t, tx, `UPDATE response_audit_intents SET action='forged' WHERE tenant_id=$1 AND intent_id='intent-1'`, tenant)
		requireMigrationWriteRejected(t, tx, `INSERT INTO response_audit_intents(tenant_id,intent_id,actor,action,target,metadata,occurred_at)
			VALUES($1,'intent-2','operator','response.halt','host-1','{"idempotency_key":"different"}'::jsonb,now())`, tenant)
		if _, err := tx.Exec(`INSERT INTO work_orders(id,tenant_id,asset_id,agent_id,capability,authorization_id,idempotency_key,not_after,time_bucket,state,signature)
			VALUES('normal-1',$1,'asset-1','agent-1','inventory','auth-1','idem-1',now()+interval '1 hour',1,'issued','signature')`, tenant); err != nil {
			t.Fatalf("insert normal work order: %v", err)
		}
		requireMigrationWriteRejected(t, tx, `INSERT INTO work_orders(id,tenant_id,asset_id,agent_id,capability,authorization_id,idempotency_key,not_after,time_bucket,state,signature,priority,response_command)
			VALUES('invalid-1',$1,'asset-1','agent-1','inventory','auth-2','idem-2',now()+interval '1 hour',2,'issued','signature',100,'{}'::jsonb)`, tenant)
	})

	if err := goose.DownTo(db, ".", 138); err == nil || !strings.Contains(err.Error(), "response audit intention history exists") {
		t.Fatalf("0139 rollback with audit history err=%v, want append-only history guard", err)
	}
}
