package postgres

import "testing"

func TestMigration0183PersonalInboxSchema(t *testing.T) {
	_, db := ownershipTestDatabase(t, 182, nil)
	for _, table := range []string{"user_notifications", "user_notification_preferences", "user_notification_tombstones"} {
		requireMigrationTable(t, db, table, true)
		requireMigrationRLS(t, db, table)
	}
	requireMigrationIndexes(t, db, "user_notifications_feed", "user_notifications_unread")
}
