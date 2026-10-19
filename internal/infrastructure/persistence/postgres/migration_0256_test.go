package postgres

import (
	"database/sql"
	"testing"
)

func TestMigration0256(t *testing.T) {
	testMigrationRoundTrip(t, 256, func(t *testing.T, db *sql.DB) {
		requireMigrationColumn(t, db, "document_commands", "checked_at")
		requireMigrationIndexes(t, db, "document_commands_fair_pending_idx", "engagements_assessment_project_idx")
	})
}
