package postgres

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0169OwnershipNotificationUpgrade(t *testing.T) {
	_, db := ownershipTestDatabase(t, 164, func(db *sql.DB) {
		withMigrationTenant(t, db, "default", func(tx *sql.Tx) {
			if _, err := tx.Exec(`INSERT INTO notification_rules(tenant_id,id,name,event_type,created_at,updated_at)
				VALUES('default','legacy-scan','Existing scan rule','scan.completed',now(),now())`); err != nil {
				t.Fatal(err)
			}
		})
	})
	requireMigrationRLS(t, db, "notification_rule_teams")
	requireMigrationIndexes(t, db, "notification_rule_teams_team")
	withMigrationTenant(t, db, "default", func(tx *sql.Tx) {
		var event string
		var all bool
		if err := tx.QueryRow(`SELECT event_type,all_teams FROM notification_rules WHERE id='legacy-scan'`).Scan(&event, &all); err != nil || event != "scan.completed" || all {
			t.Fatalf("legacy subscription changed: event=%s all=%v err=%v", event, all, err)
		}
		if _, err := tx.Exec(`INSERT INTO notification_rules(tenant_id,id,name,event_type,all_teams,created_at,updated_at)
			VALUES('default','ownership','Ownership','finding.ownership_changed',true,now(),now())`); err != nil {
			t.Fatal(err)
		}
	})
	if err := goose.DownTo(db, ".", 164); err == nil {
		t.Fatal("downgrade silently discarded an ownership subscription")
	}
	withMigrationTenant(t, db, "default", func(tx *sql.Tx) {
		if _, err := tx.Exec(`DELETE FROM notification_rules WHERE id='ownership'`); err != nil {
			t.Fatal(err)
		}
	})
	if err := goose.DownTo(db, ".", 164); err != nil {
		t.Fatal(err)
	}
	requireMigrationTable(t, db, "notification_rule_teams", false)
	if err := goose.UpTo(db, ".", 165); err != nil {
		t.Fatal(err)
	}
	withMigrationTenant(t, db, "default", func(tx *sql.Tx) {
		var count int
		if err := tx.QueryRow(`SELECT count(*) FROM notification_rules WHERE id='legacy-scan' AND event_type='scan.completed' AND NOT all_teams`).Scan(&count); err != nil || count != 1 {
			t.Fatalf("legacy rule lost across rollback/upgrade: %d %v", count, err)
		}
	})
}
