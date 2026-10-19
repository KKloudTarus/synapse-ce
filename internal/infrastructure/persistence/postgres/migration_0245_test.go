package postgres

import (
	"database/sql"
	"testing"
)

func TestMigration0245(t *testing.T) {
	testMigrationRoundTrip(t, 245, func(t *testing.T, db *sql.DB) {
		requireMigrationColumn(t, db, "ticket_groups", "revision")
	})
}
