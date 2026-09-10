package postgres

import (
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0161NotificationFramework(t *testing.T) {
	isolated := newIsolatedMigrationDB(t, 161, 160)
	db := isolated.db
	if err := goose.UpTo(db, ".", 161); err != nil {
		t.Fatalf("apply 0161: %v", err)
	}
	for _, table := range []string{"notification_channels", "notification_channel_versions", "notification_rules", "notification_rule_channels", "notification_events", "notification_deliveries", "notification_delivery_attempts", "notification_source_state"} {
		requireMigrationTable(t, db, table, true)
		requireMigrationRLS(t, db, table)
	}
	requireMigrationIndexes(t, db, "idx_notification_deliveries_history", "idx_notification_deliveries_state")
	if err := goose.DownTo(db, ".", 160); err != nil {
		t.Fatalf("roll back 0161: %v", err)
	}
	requireMigrationTable(t, db, "notification_channels", false)
}
