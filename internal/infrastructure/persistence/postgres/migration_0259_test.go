package postgres

import (
	"database/sql"
	"testing"
)

func TestMigration0259(t *testing.T) {
	testMigrationRoundTrip(t, 259, func(t *testing.T, db *sql.DB) {
		requireMigrationIndexes(t, db, "document_schedules_ready_idx", "document_schedule_occurrences_ready_idx")
	})
}
