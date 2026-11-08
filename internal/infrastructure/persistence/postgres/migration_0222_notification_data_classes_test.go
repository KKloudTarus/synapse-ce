package postgres

import (
	"database/sql"
	"testing"
)

// The base is 221, the last migration before this one.
const migration0222Base = 221

// TestMigration0222NotificationDataClasses checks that existing channels get their type's default
// class, that the engagement override table has forced RLS and refuses unknown values, and that a
// deleted engagement takes its override with it.
func TestMigration0222NotificationDataClasses(t *testing.T) {
	inTenant := func(db *sql.DB, stmt string, args ...any) error {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`SELECT set_config('app.current_tenant','t-class',true)`); err != nil {
			return err
		}
		if _, err := tx.Exec(stmt, args...); err != nil {
			return err
		}
		return tx.Commit()
	}
	_, db := ownershipTestDatabase(t, migration0222Base, func(db *sql.DB) {
		if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES('t-class','Class') ON CONFLICT DO NOTHING`); err != nil {
			t.Fatal(err)
		}
		for _, stmt := range []string{
			`INSERT INTO notification_channels(tenant_id,id,name,channel_type,created_at,updated_at) VALUES('t-class','slack','Room','slack',now(),now())`,
			`INSERT INTO notification_channels(tenant_id,id,name,channel_type,created_at,updated_at) VALUES('t-class','teams','Team','teams',now(),now())`,
			`INSERT INTO notification_channels(tenant_id,id,name,channel_type,created_at,updated_at) VALUES('t-class','mail','Mail','email',now(),now())`,
		} {
			if err := inTenant(db, stmt); err != nil {
				t.Fatal(err)
			}
		}
	})
	requireMigrationTable(t, db, "notification_engagement_settings", true)
	requireMigrationRLS(t, db, "notification_engagement_settings")

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant','t-class',true)`); err != nil {
		t.Fatal(err)
	}
	classes := map[string]string{}
	rows, err := tx.Query(`SELECT id,data_class FROM notification_channels WHERE tenant_id='t-class'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id, class string
		if err := rows.Scan(&id, &class); err != nil {
			t.Fatal(err)
		}
		classes[id] = class
	}
	_ = rows.Close()
	_ = tx.Rollback()
	// An email channel shows the summary default; webhooks are moved again by #1367.
	if classes["slack"] != "signal" || classes["teams"] != "signal" || classes["mail"] != "summary" {
		t.Fatalf("existing channel classes = %v, want signal for slack and teams and summary for email", classes)
	}

	if err := inTenant(db, `INSERT INTO engagements(id,tenant_id,name) VALUES('eng-class','t-class','E')`); err != nil {
		t.Fatal(err)
	}
	insert := `INSERT INTO notification_engagement_settings(tenant_id,engagement_id,external_notifications,revision,updated_at,updated_by) VALUES('t-class','eng-class',$1,1,now(),'admin')`
	if err := inTenant(db, insert, "everything"); err == nil {
		t.Fatal("an unknown override value was stored")
	}
	if err := inTenant(db, `UPDATE notification_channels SET data_class='secret' WHERE id='mail'`); err == nil {
		t.Fatal("an unknown channel class was stored")
	}
	if err := inTenant(db, insert, "none"); err != nil {
		t.Fatal(err)
	}
	// A setting cannot name another tenant's engagement: the foreign key carries the tenant.
	other, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`INSERT INTO tenants(id,name) VALUES('t-other','Other') ON CONFLICT DO NOTHING`,
		`SELECT set_config('app.current_tenant','t-other',true)`,
		`INSERT INTO engagements(id,tenant_id,name) VALUES('eng-other','t-other','O')`,
	} {
		if _, err := other.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := other.Commit(); err != nil {
		t.Fatal(err)
	}
	foreign := `INSERT INTO notification_engagement_settings(tenant_id,engagement_id,external_notifications,revision,updated_at,updated_by) VALUES('t-class','eng-other','none',1,now(),'admin')`
	if err := inTenant(db, foreign); err == nil {
		t.Fatal("a setting named another tenant's engagement")
	}
	if err := inTenant(db, `DELETE FROM engagements WHERE id='eng-class'`); err != nil {
		t.Fatal(err)
	}
	// RLS is forced, so the count runs inside the tenant; outside it every count would be zero.
	count, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = count.Rollback() }()
	if _, err := count.Exec(`SELECT set_config('app.current_tenant','t-class',true)`); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := count.QueryRow(`SELECT count(*) FROM notification_engagement_settings`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("%d overrides survived their engagement", left)
	}
}
