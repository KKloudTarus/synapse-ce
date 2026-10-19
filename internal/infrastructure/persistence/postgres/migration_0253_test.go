package postgres

import (
	"database/sql"
	"testing"
)

func TestMigration0253(t *testing.T) {
	testMigrationRoundTrip(t, 253, func(t *testing.T, db *sql.DB) {
		requireMigrationFunction(t, db, "synapse_can_release_document")
	})
}
