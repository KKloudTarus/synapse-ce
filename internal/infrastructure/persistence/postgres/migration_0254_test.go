package postgres

import (
	"database/sql"
	"testing"
)

func TestMigration0254(t *testing.T) {
	testMigrationRoundTrip(t, 254, func(t *testing.T, db *sql.DB) {
		requireDocumentIntentMarkerConstraint(t, db, true)
	})
}
