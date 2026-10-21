package postgres

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0263ProviderRetryScheduleUpgradeRollbackAndReapply(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 263, 262)
	db := isolate.db
	const documentTenant = "migration-0263-document"
	const ticketTenant = "migration-0251"
	seedDocumentRemoteRevisionLegacyRows(t, db, documentTenant)
	seedTicketMigrationIntent(t, db, "migration-0263-ticket")
	withMigrationTenant(t, db, documentTenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO document_commands
			(tenant_id,intent_id,actor_user_id,actor_membership_id,actor_person_id,connection_revision,credential_revision,read_group,artifact,created_at,updated_at)
			VALUES($1,$2,'reviewer','','',1,0,'reviewers','{}'::jsonb,now(),now())`, documentTenant, documentTenant+"-intent"); err != nil {
			t.Fatalf("seed document retry command: %v", err)
		}
	})

	if err := goose.UpTo(db, ".", 263); err != nil {
		t.Fatalf("apply provider retry scheduling: %v", err)
	}
	for _, table := range []string{"document_commands", "ticket_inbound_poll_progress"} {
		requireMigrationRLS(t, db, table)
	}
	requireMigrationColumn(t, db, "document_commands", "next_attempt_at")
	requireMigrationColumn(t, db, "ticket_inbound_poll_progress", "next_poll_at")
	requireMigrationIndexes(t, db, "document_commands_due_idx", "document_intents_eligible_queue_idx", "ticket_inbound_poll_progress_due_idx")

	withMigrationTenant(t, db, documentTenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`UPDATE document_commands SET next_attempt_at=clock_timestamp()+interval '1 hour' WHERE tenant_id=$1`, documentTenant); err != nil {
			t.Fatalf("defer document retry: %v", err)
		}
	})
	if err := goose.DownTo(db, ".", 262); err == nil || !strings.Contains(err.Error(), "future provider deferrals or poll claims") {
		t.Fatalf("rollback with future document retry err=%v", err)
	}
	for _, table := range []string{"document_commands", "ticket_inbound_poll_progress"} {
		requireMigrationColumn(t, db, table, map[string]string{"document_commands": "next_attempt_at", "ticket_inbound_poll_progress": "next_poll_at"}[table])
		requireMigrationRLS(t, db, table)
	}

	withMigrationTenant(t, db, documentTenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`UPDATE document_commands SET next_attempt_at=NULL WHERE tenant_id=$1`, documentTenant); err != nil {
			t.Fatalf("clear document retry: %v", err)
		}
	})
	withMigrationTenant(t, db, ticketTenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`UPDATE ticket_inbound_poll_progress SET next_poll_at=clock_timestamp()+interval '1 hour' WHERE intent_id='migration-0263-ticket'`); err != nil {
			t.Fatalf("reserve inbound poll: %v", err)
		}
	})
	if err := goose.DownTo(db, ".", 262); err == nil || !strings.Contains(err.Error(), "future provider deferrals or poll claims") {
		t.Fatalf("rollback with future inbound poll err=%v", err)
	}
	for _, table := range []string{"document_commands", "ticket_inbound_poll_progress"} {
		requireMigrationRLS(t, db, table)
	}

	withMigrationTenant(t, db, ticketTenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`UPDATE ticket_inbound_poll_progress SET next_poll_at='-infinity'::timestamptz WHERE intent_id='migration-0263-ticket'`); err != nil {
			t.Fatalf("clear inbound poll reservation: %v", err)
		}
	})
	if err := goose.DownTo(db, ".", 262); err != nil {
		t.Fatalf("rollback cleared provider retry scheduling: %v", err)
	}
	if err := goose.UpTo(db, ".", 263); err != nil {
		t.Fatalf("reapply provider retry scheduling: %v", err)
	}
	for _, table := range []string{"document_commands", "ticket_inbound_poll_progress"} {
		requireMigrationRLS(t, db, table)
	}
}
