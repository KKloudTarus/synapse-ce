package postgres

import (
	"database/sql"
	"testing"
)

func TestMigration0248(t *testing.T) {
	testMigrationRoundTrip(t, 248, func(t *testing.T, db *sql.DB) {
		for _, table := range []string{"ticket_external_observations", "ticket_retest_proposals", "ticket_external_comments"} {
			requireMigrationTable(t, db, table, true)
			requireMigrationRLS(t, db, table)
		}
	})
}
