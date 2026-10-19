package postgres

import (
	"database/sql"
	"testing"
)

func TestMigration0251(t *testing.T) {
	testMigrationRoundTrip(t, 251, func(t *testing.T, db *sql.DB) {
		for _, table := range []string{"ticket_inbound_poll_progress", "ticket_inbound_poll_backfill_cursors"} {
			requireMigrationTable(t, db, table, true)
			requireMigrationRLS(t, db, table)
		}
		requireMigrationTrigger(t, db, "ticket_intents", "ticket_inbound_poll_target_after_write")
	})
}
