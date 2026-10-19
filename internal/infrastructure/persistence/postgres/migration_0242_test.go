package postgres

import (
	"database/sql"
	"testing"
)

func TestMigration0242(t *testing.T) {
	testMigrationRoundTrip(t, 242, func(t *testing.T, db *sql.DB) {
		requireMigrationTable(t, db, "ticket_auto_push_receipts", true)
		requireMigrationRLS(t, db, "ticket_auto_push_receipts")
		requireMigrationIndexes(t, db, "ticket_mappings_auto_push_scope_idx", "ticket_auto_push_receipts_pending_idx")
		requireMigrationFunction(t, db, "ticket_capture_auto_push_event")
	})
}
