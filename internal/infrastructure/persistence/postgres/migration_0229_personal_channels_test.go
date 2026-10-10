package postgres

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
)

// Migration 0229 (#1415, #1418, #1419, #1420): the new tables have RLS, the Teams link offers are
// owner-only, and the migration rolls back and forward cleanly with Slack data in place.
func TestMigration0229PersonalChannels(t *testing.T) {
	isolated := newIsolatedMigrationDB(t, 229, 229)
	db := isolated.db
	for _, table := range []string{"notification_personal_defaults", "user_teams_conversations"} {
		requireMigrationTable(t, db, table, true)
		requireMigrationRLS(t, db, table)
	}
	var forced bool
	if err := db.QueryRow(`SELECT relforcerowsecurity FROM pg_class WHERE oid='public.teams_link_offers'::regclass`).Scan(&forced); err != nil || !forced {
		t.Fatalf("teams_link_offers forced RLS = %v %v", forced, err)
	}
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES('m224','m224')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users(id,name,role,api_key_hash,tenant_id,disabled) VALUES('u1','U','member','hash-m224','m224',false)`); err != nil {
		t.Fatal(err)
	}
	withMigrationTenant(t, db, "m224", func(tx *sql.Tx) {
		if _, err := tx.Exec(`INSERT INTO user_contacts(tenant_id,id,user_id,kind,source,value,verified_at,version,created_at,updated_at) VALUES('m224','c1','u1','slack','manual','T01:U01',now(),1,now(),now())`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO user_notification_preferences(tenant_id,user_id,event_type,channel,state,revision,updated_at) VALUES('m224','u1','finding.ownership_changed','slack','enabled',1,now())`); err != nil {
			t.Fatal(err)
		}
		requireMigrationWriteRejected(t, tx, `INSERT INTO user_notification_preferences(tenant_id,user_id,event_type,channel,state,revision,updated_at) VALUES('m224','u1','scan.completed','pager','enabled',1,now())`)
		requireMigrationWriteRejected(t, tx, `INSERT INTO notification_personal_defaults(tenant_id,event_type,channel,enabled,revision,updated_at,updated_by) VALUES('m224','scan.completed','in_app_x',true,1,now(),'a')`)
	})
	var accepted bool
	if err := db.QueryRow(`SELECT synapse_offer_teams_link(repeat('a',64), repeat('c',64), 'sealed', now() + interval '10 minutes')`).Scan(&accepted); err != nil || !accepted {
		t.Fatalf("offer = %v %v", accepted, err)
	}
	if err := goose.DownTo(db, ".", 228); err != nil {
		t.Fatalf("down to 0228: %v", err)
	}
	requireMigrationTable(t, db, "notification_personal_defaults", false)
	requireMigrationTable(t, db, "teams_link_offers", false)
	if err := goose.UpTo(db, ".", 229); err != nil {
		t.Fatalf("up to 0229 again: %v", err)
	}
	requireMigrationTable(t, db, "user_teams_conversations", true)
}
