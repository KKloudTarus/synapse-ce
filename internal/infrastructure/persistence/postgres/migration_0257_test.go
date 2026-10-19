package postgres

import (
	"database/sql"
	"testing"
)

func TestMigration0257(t *testing.T) {
	testMigrationRoundTrip(t, 257, func(t *testing.T, db *sql.DB) {
		for _, table := range []string{"document_schedules", "document_schedule_occurrences", "document_schedule_deliveries"} {
			requireMigrationTable(t, db, table, true)
			requireMigrationRLS(t, db, table)
		}
	})
}
