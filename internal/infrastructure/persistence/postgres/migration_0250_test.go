package postgres

import (
	"database/sql"
	"testing"
)

func TestMigration0250(t *testing.T) {
	testMigrationRoundTrip(t, 250, func(t *testing.T, db *sql.DB) {
		requireMigrationColumn(t, db, "ticket_external_observations", "pending_done")
		requireMigrationColumn(t, db, "ticket_retest_proposals", "resolution_name")
		requireMigrationRLS(t, db, "ticket_external_comments")
	})
}
