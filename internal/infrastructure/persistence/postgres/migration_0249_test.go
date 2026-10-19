package postgres

import (
	"database/sql"
	"testing"
)

func TestMigration0249(t *testing.T) {
	testMigrationRoundTrip(t, 249, func(t *testing.T, db *sql.DB) {
		requireMigrationTable(t, db, "ticket_inbound_config", true)
		requireMigrationRLS(t, db, "ticket_inbound_config")
		requireMigrationFunction(t, db, "synapse_provision_jira_inbound_webhook")
		requireMigrationFunction(t, db, "synapse_rotate_jira_inbound_webhook")
	})
}
