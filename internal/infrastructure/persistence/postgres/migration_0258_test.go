package postgres

import (
	"database/sql"
	"testing"
)

func TestMigration0258(t *testing.T) {
	testMigrationRoundTrip(t, 258, func(t *testing.T, db *sql.DB) {
		requireMigrationIndexes(t, db, "ticket_intents_inbound_remote_done_create_idx", "ticket_external_comments_finding_recent_idx")
	})
}
