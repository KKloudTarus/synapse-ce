package postgres

import (
	"database/sql"
	"testing"
)

func TestMigration0246(t *testing.T) {
	testMigrationRoundTrip(t, 246, func(t *testing.T, db *sql.DB) {
		requireMigrationColumn(t, db, "ticket_status_sync", "checked_at")
		requireMigrationColumn(t, db, "ticket_status_sync", "version")
		requireMigrationIndexes(t, db, "ticket_status_sync_pending_idx")
	})
}
