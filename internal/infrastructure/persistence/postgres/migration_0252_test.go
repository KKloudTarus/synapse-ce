package postgres

import (
	"database/sql"
	"testing"
)

func TestMigration0252(t *testing.T) {
	testMigrationRoundTrip(t, 252, func(t *testing.T, db *sql.DB) {
		requireMigrationTable(t, db, "document_commands", true)
		requireMigrationRLS(t, db, "document_commands")
		requireMigrationColumn(t, db, "document_links", "retired_at")
		requireMigrationIndexes(t, db, "document_commands_pending_idx")
	})
}
