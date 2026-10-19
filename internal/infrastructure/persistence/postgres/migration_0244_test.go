package postgres

import (
	"database/sql"
	"testing"
)

func TestMigration0244(t *testing.T) {
	testMigrationRoundTrip(t, 244, func(t *testing.T, db *sql.DB) {
		requireMigrationTable(t, db, "ticket_status_sync", true)
		requireMigrationRLS(t, db, "ticket_status_sync")
		requireMigrationIndexes(t, db, "ticket_status_sync_pending_idx")
	})
}
