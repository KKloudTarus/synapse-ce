package postgres

import (
	"database/sql"
	"testing"
)

func TestMigration0243(t *testing.T) {
	testMigrationRoundTrip(t, 243, func(t *testing.T, db *sql.DB) {
		for _, table := range []string{"ticket_groups", "ticket_group_members"} {
			requireMigrationTable(t, db, table, true)
			requireMigrationRLS(t, db, table)
		}
	})
}
