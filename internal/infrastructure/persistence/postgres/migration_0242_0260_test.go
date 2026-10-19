package postgres

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
)

// TestMigrations0242To0260ApplyWithForcedTenantRLS exercises the production
// migration entry point from the preceding schema. Each subtest names
// the migration artifact it protects so a later edit cannot silently omit one
// of the incremental schema contracts.
func TestMigrations0242To0260ApplyWithForcedTenantRLS(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 260, 241)
	if err := Migrate(context.Background(), isolate.dsn); err != nil {
		t.Fatalf("apply migration sequence through production entry point: %v", err)
	}
	db := isolate.db

	tests := []struct {
		name  string
		check func(*testing.T)
	}{
		{"0242 auto-push receipts", func(t *testing.T) {
			requireMigrationTable(t, db, "ticket_auto_push_receipts", true)
			requireMigrationRLS(t, db, "ticket_auto_push_receipts")
			requireMigrationIndexes(t, db, "ticket_mappings_auto_push_scope_idx", "ticket_auto_push_receipts_pending_idx")
			requireMigrationFunction(t, db, "ticket_capture_auto_push_event")
		}},
		{"0243 ticket grouping", func(t *testing.T) {
			for _, table := range []string{"ticket_groups", "ticket_group_members"} {
				requireMigrationTable(t, db, table, true)
				requireMigrationRLS(t, db, table)
			}
		}},
		{"0244 status synchronisation", func(t *testing.T) {
			requireMigrationTable(t, db, "ticket_status_sync", true)
			requireMigrationRLS(t, db, "ticket_status_sync")
		}},
		{"0245 group command revision", func(t *testing.T) { requireMigrationColumn(t, db, "ticket_groups", "revision") }},
		{"0246 status progress", func(t *testing.T) {
			requireMigrationColumn(t, db, "ticket_status_sync", "checked_at")
			requireMigrationColumn(t, db, "ticket_status_sync", "version")
		}},
		{"0247 status episode", func(t *testing.T) { requireMigrationColumn(t, db, "ticket_status_sync", "episode") }},
		{"0248 inbound observations", func(t *testing.T) {
			for _, table := range []string{"ticket_external_observations", "ticket_retest_proposals", "ticket_external_comments"} {
				requireMigrationTable(t, db, table, true)
				requireMigrationRLS(t, db, table)
			}
		}},
		{"0249 inbound configuration", func(t *testing.T) {
			requireMigrationTable(t, db, "ticket_inbound_config", true)
			requireMigrationRLS(t, db, "ticket_inbound_config")
			requireMigrationFunction(t, db, "synapse_provision_jira_inbound_webhook")
			requireMigrationFunction(t, db, "synapse_rotate_jira_inbound_webhook")
		}},
		{"0250 inbound status attribution", func(t *testing.T) {
			requireMigrationColumn(t, db, "ticket_external_observations", "pending_done")
			requireMigrationColumn(t, db, "ticket_retest_proposals", "resolution_name")
		}},
		{"0251 bounded inbound catchup", func(t *testing.T) {
			for _, table := range []string{"ticket_inbound_poll_progress", "ticket_inbound_poll_backfill_cursors"} {
				requireMigrationTable(t, db, table, true)
				requireMigrationRLS(t, db, table)
			}
			requireMigrationTrigger(t, db, "ticket_intents", "ticket_inbound_poll_target_after_write")
		}},
		{"0252 document commands", func(t *testing.T) {
			requireMigrationTable(t, db, "document_commands", true)
			requireMigrationRLS(t, db, "document_commands")
			requireMigrationColumn(t, db, "document_links", "retired_at")
		}},
		{"0253 document release authority", func(t *testing.T) { requireMigrationFunction(t, db, "synapse_can_release_document") }},
		{"0254 document intent marker", func(t *testing.T) {
			requireDocumentIntentMarkerConstraint(t, db, true)
		}},
		{"0255 unbound release refusal", func(t *testing.T) {
			var allowed bool
			if err := db.QueryRow(`SELECT synapse_can_release_document('','','','')`).Scan(&allowed); err != nil || allowed {
				t.Fatalf("unbound document release allowed=%t err=%v", allowed, err)
			}
		}},
		{"0256 document queue indexes", func(t *testing.T) {
			requireMigrationIndexes(t, db, "document_commands_fair_pending_idx", "engagements_assessment_project_idx")
		}},
		{"0257 report schedules", func(t *testing.T) {
			for _, table := range []string{"document_schedules", "document_schedule_occurrences", "document_schedule_deliveries"} {
				requireMigrationTable(t, db, table, true)
				requireMigrationRLS(t, db, table)
			}
		}},
		{"0258 inbound read indexes", func(t *testing.T) {
			requireMigrationIndexes(t, db, "ticket_intents_inbound_remote_done_create_idx", "ticket_external_comments_finding_recent_idx")
		}},
		{"0259 schedule ready indexes", func(t *testing.T) {
			requireMigrationIndexes(t, db, "document_schedules_ready_idx", "document_schedule_occurrences_ready_idx")
		}},
		{"0260 scan job purpose", func(t *testing.T) {
			requireMigrationColumn(t, db, "scan_jobs", "purpose")
			requireMigrationConstraint(t, db, "scan_jobs", "scan_jobs_purpose_known")
			requireMigrationTrigger(t, db, "scan_jobs", "scan_jobs_immutable_purpose")
			requireMigrationIndexes(t, db, "idx_scan_jobs_project_analysis_latest")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, test.check)
	}
}

func testMigrationRoundTrip(t *testing.T, version int64, check func(*testing.T, *sql.DB)) {
	t.Helper()
	isolate := newIsolatedMigrationDB(t, int(version), version-1)
	if err := goose.UpTo(isolate.db, ".", version); err != nil {
		t.Fatalf("apply migration %04d: %v", version, err)
	}
	check(t, isolate.db)
	if err := goose.DownTo(isolate.db, ".", version-1); err != nil {
		t.Fatalf("reverse empty migration %04d: %v", version, err)
	}
	if err := Migrate(context.Background(), isolate.dsn); err != nil {
		t.Fatalf("reapply migration %04d through production entry point: %v", version, err)
	}
	check(t, isolate.db)
}

func requireMigrationColumn(t *testing.T, db *sql.DB, table, column string) {
	t.Helper()
	var found bool
	if err := db.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema='public' AND table_name=$1 AND column_name=$2
	)`, table, column).Scan(&found); err != nil || !found {
		t.Fatalf("migration column %s.%s exists=%t err=%v", table, column, found, err)
	}
}

func requireMigrationConstraint(t *testing.T, db *sql.DB, table, constraint string) {
	t.Helper()
	var found bool
	if err := db.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM pg_constraint
		WHERE conrelid=$1::regclass AND conname=$2
	)`, table, constraint).Scan(&found); err != nil || !found {
		t.Fatalf("migration constraint %s.%s exists=%t err=%v", table, constraint, found, err)
	}
}

func requireMigrationFunction(t *testing.T, db *sql.DB, name string) {
	t.Helper()
	var found bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_proc WHERE pronamespace='public'::regnamespace AND proname=$1)`, name).Scan(&found); err != nil || !found {
		t.Fatalf("migration function %s exists=%t err=%v", name, found, err)
	}
}

func requireMigrationTrigger(t *testing.T, db *sql.DB, table, trigger string) {
	t.Helper()
	var found bool
	if err := db.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM pg_trigger WHERE tgrelid=$1::regclass AND tgname=$2 AND NOT tgisinternal
	)`, table, trigger).Scan(&found); err != nil || !found {
		t.Fatalf("migration trigger %s.%s exists=%t err=%v", table, trigger, found, err)
	}
}

func requireDocumentIntentMarkerConstraint(t *testing.T, db *sql.DB, want bool) {
	t.Helper()
	var found bool
	if err := db.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM pg_constraint
		WHERE conrelid='document_intents'::regclass AND contype='c'
		  AND pg_get_constraintdef(oid) LIKE '%correlation_marker%'
		  AND pg_get_constraintdef(oid) LIKE '%synapse-intent-%'
	)`).Scan(&found); err != nil || found != want {
		t.Fatalf("document intent marker constraint exists=%t want=%t err=%v", found, want, err)
	}
}

func TestMigration0251DefersExistingIntentCatchupAndCapturesFutureIntent(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 251, 250)
	db := isolate.db
	seedTicketMigrationIntent(t, db, "before-0251")
	if err := goose.UpTo(db, ".", 251); err != nil {
		t.Fatalf("apply inbound progress migration: %v", err)
	}
	var existing int
	if err := db.QueryRow(`SELECT count(*) FROM ticket_inbound_poll_progress`).Scan(&existing); err != nil || existing != 0 {
		t.Fatalf("migration eagerly backfilled %d intents: %v", existing, err)
	}
	withMigrationTenant(t, db, "migration-0251", func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO ticket_intents
			(id,tenant_id,integration_id,mapping_id,finding_id,engagement_id,action,request_key,payload_digest,correlation_marker,state,remote_id,remote_url,created_at,updated_at)
			VALUES ('after-0251','migration-0251','migration-0251-integration','migration-0251-mapping','migration-0251-finding','migration-0251-engagement','create','after-0251',repeat('b',64),'synapse-intent-after-0251','done','SEC-2','https://jira.example/browse/SEC-2',now(),now())`); err != nil {
			t.Fatalf("write post-migration ticket intent: %v", err)
		}
		var captured int
		if err := tx.QueryRow(`SELECT count(*) FROM ticket_inbound_poll_progress WHERE intent_id='after-0251'`).Scan(&captured); err != nil || captured != 1 {
			t.Fatalf("trigger captured=%d err=%v", captured, err)
		}
	})
}

func TestMigration0254RepairsAndReversesDocumentIntentMarkerConstraint(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 254, 253)
	db := isolate.db
	dropDocumentIntentMarkerConstraint(t, db)
	requireDocumentIntentMarkerConstraint(t, db, false)
	if err := goose.UpTo(db, ".", 254); err != nil {
		t.Fatalf("repair document intent marker constraint: %v", err)
	}
	requireDocumentIntentMarkerConstraint(t, db, true)
	if err := goose.DownTo(db, ".", 253); err != nil {
		t.Fatalf("reverse repaired document intent marker constraint: %v", err)
	}
	requireDocumentIntentMarkerConstraint(t, db, false)
	if err := goose.UpTo(db, ".", 254); err != nil {
		t.Fatalf("reapply document intent marker constraint: %v", err)
	}
	requireDocumentIntentMarkerConstraint(t, db, true)
}

func TestMigration0260MakesScanJobPurposeImmutable(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 260, 259)
	db := isolate.db
	if err := goose.UpTo(db, ".", 260); err != nil {
		t.Fatalf("apply scan job purpose migration: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO scan_jobs(id,engagement_id,target,kind,status,stage,progress,started_at,purpose)
		VALUES('migration-0260-job','migration-0260-engagement','repo','sca','running','queued',0,now(),'project_source')`); err != nil {
		t.Fatalf("insert project source scan job: %v", err)
	}
	if _, err := db.Exec(`UPDATE scan_jobs SET purpose='' WHERE id='migration-0260-job'`); err == nil {
		t.Fatal("scan job purpose update succeeded")
	}
	if _, err := db.Exec(`INSERT INTO scan_jobs(id,engagement_id,target,kind,status,stage,progress,started_at,purpose)
		VALUES('migration-0260-invalid','migration-0260-engagement','repo','sca','running','queued',0,now(),'unknown')`); err == nil {
		t.Fatal("scan job accepted unknown purpose")
	}
}

func TestMigration0252RefusesRollbackWithDurableDocumentCommand(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 252, 251)
	db := isolate.db
	if err := goose.UpTo(db, ".", 252); err != nil {
		t.Fatalf("apply document command migration: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES('migration-0252','Migration 0252')`); err != nil {
		t.Fatalf("seed document command tenant: %v", err)
	}
	withMigrationTenant(t, db, "migration-0252", func(tx *sql.Tx) {
		for _, statement := range []string{
			`INSERT INTO engagements(id,tenant_id,name) VALUES('migration-0252-engagement','migration-0252','Migration engagement')`,
			`INSERT INTO integrations(id,tenant_id,provider,display_name,endpoint,created_at,updated_at) VALUES('migration-0252-integration','migration-0252','confluence-cloud','Migration Confluence','https://wiki.example',now(),now())`,
			`INSERT INTO document_intents(id,tenant_id,integration_id,source_kind,source_ref,engagement_id,container,action,request_key,payload_digest,content_hash,correlation_marker,state,remote_id,remote_url,remote_version,created_at,updated_at) VALUES('migration-0252-intent','migration-0252','migration-0252-integration','engagement_report','r','migration-0252-engagement','SEC','create','migration-0252',repeat('a',64),repeat('b',64),'synapse-intent-migration-0252-intent','done','123','https://wiki.example/p',1,now(),now())`,
			`INSERT INTO document_commands(tenant_id,intent_id,actor_user_id,actor_membership_id,actor_person_id,connection_revision,credential_revision,read_group,artifact,created_at,updated_at) VALUES('migration-0252','migration-0252-intent','admin','','',1,0,'reviewers','{}'::jsonb,now(),now())`,
		} {
			if _, err := tx.Exec(statement); err != nil {
				t.Fatalf("seed durable document command: %v", err)
			}
		}
	})
	if err := goose.DownTo(db, ".", 251); err == nil || !strings.Contains(err.Error(), "durable command data") {
		t.Fatalf("rollback with durable document command err=%v", err)
	}
	for _, table := range []string{"document_commands", "document_links"} {
		requireMigrationRLS(t, db, table)
	}
}

func dropDocumentIntentMarkerConstraint(t *testing.T, db *sql.DB) {
	t.Helper()
	var statement string
	if err := db.QueryRow(`SELECT format('ALTER TABLE document_intents DROP CONSTRAINT %I', conname)
		FROM pg_constraint
		WHERE conrelid='document_intents'::regclass AND contype='c'
		  AND pg_get_constraintdef(oid) LIKE '%correlation_marker%'
		  AND pg_get_constraintdef(oid) LIKE '%synapse-intent-%'
		LIMIT 1`).Scan(&statement); err != nil {
		t.Fatalf("locate document intent marker constraint: %v", err)
	}
	if _, err := db.Exec(statement); err != nil {
		t.Fatalf("remove document intent marker constraint: %v", err)
	}
}

func seedTicketMigrationIntent(t *testing.T, db *sql.DB, intentID string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES('migration-0251','Migration 0251')`); err != nil {
		t.Fatalf("seed migration tenant: %v", err)
	}
	withMigrationTenant(t, db, "migration-0251", func(tx *sql.Tx) {
		for _, statement := range []string{
			`INSERT INTO engagements(id,tenant_id,name) VALUES('migration-0251-engagement','migration-0251','Migration engagement')`,
			`INSERT INTO findings(id,tenant_id,engagement_id,title) VALUES('migration-0251-finding','migration-0251','migration-0251-engagement','Migration finding')`,
			`INSERT INTO integrations(id,tenant_id,provider,display_name,endpoint,created_at,updated_at) VALUES('migration-0251-integration','migration-0251','jira-cloud','Migration Jira','https://jira.example',now(),now())`,
			`INSERT INTO ticket_mappings(id,tenant_id,integration_id,engagement_id,project_key,issue_type,version,created_at,updated_at) VALUES('migration-0251-mapping','migration-0251','migration-0251-integration','migration-0251-engagement','SEC','10001',1,now(),now())`,
		} {
			if _, err := tx.Exec(statement); err != nil {
				t.Fatalf("seed migration dependency: %v", err)
			}
		}
		if _, err := tx.Exec(`INSERT INTO ticket_intents
			(id,tenant_id,integration_id,mapping_id,finding_id,engagement_id,action,request_key,payload_digest,correlation_marker,state,remote_id,remote_url,created_at,updated_at)
			VALUES ($1,'migration-0251','migration-0251-integration','migration-0251-mapping','migration-0251-finding','migration-0251-engagement','create','before-0251',repeat('a',64),'synapse-intent-' || $1,'done','SEC-1','https://jira.example/browse/SEC-1',now(),now())`, intentID); err != nil {
			t.Fatalf("seed pre-migration completed ticket intent: %v", err)
		}
	})
}
