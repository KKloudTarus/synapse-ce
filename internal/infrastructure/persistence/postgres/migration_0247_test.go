package postgres

import (
	"database/sql"
	"testing"
)

func TestMigration0247(t *testing.T) {
	testMigrationRoundTrip(t, 247, func(t *testing.T, db *sql.DB) {
		requireMigrationColumn(t, db, "ticket_status_sync", "episode")
	})
}
