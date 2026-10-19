package postgres

import (
	"database/sql"
	"testing"
)

func TestMigration0255(t *testing.T) {
	testMigrationRoundTrip(t, 255, func(t *testing.T, db *sql.DB) {
		var allowed bool
		if err := db.QueryRow(`SELECT synapse_can_release_document('','','','')`).Scan(&allowed); err != nil || allowed {
			t.Fatalf("unbound document release allowed=%t err=%v", allowed, err)
		}
	})
}
