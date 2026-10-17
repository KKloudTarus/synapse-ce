package postgres

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0240RuleSelectionCompatibility(t *testing.T) {
	isolate := newIsolatedMigrationDB(t, 240, 239)
	db := isolate.db
	if _, err := db.Exec(`INSERT INTO tenants(id,name) VALUES('selection-a','Selection A'),('selection-b','Selection B')`); err != nil {
		t.Fatal(err)
	}
	tenantTx := func(tenant string, fn func(*sql.Tx) error) error {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`SELECT set_config('app.current_tenant',$1,true)`, tenant); err != nil {
			return err
		}
		if err := fn(tx); err != nil {
			return err
		}
		return tx.Commit()
	}
	if err := tenantTx("selection-a", func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO notification_rules(tenant_id,id,name,enabled,event_type,revision,created_at,updated_at) VALUES('selection-a','rule','Rule',true,'engagement.created',1,now(),now())`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpTo(db, ".", 240); err != nil {
		t.Fatal(err)
	}
	if err := tenantTx("selection-a", func(tx *sql.Tx) error {
		var count int
		err := tx.QueryRow(`SELECT cardinality(event_types) FROM notification_rules WHERE id='rule'`).Scan(&count)
		if err == nil && count != 0 {
			t.Fatalf("legacy selection cardinality=%d", count)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for name, selection := range map[string]string{
		"primary mismatch": "{finding.created,engagement.created}",
		"wildcard":         "{engagement.created,*}",
		"null member":      "{engagement.created,NULL}",
		"nested array":     "{{engagement.created,finding.created}}",
		"too many":         "{engagement.created,finding.created,finding.commented,finding.status_changed,engagement.status_changed,scan.completed,incident.created,sla.breached,risk_acceptance.created}",
	} {
		t.Run(name, func(t *testing.T) {
			err := tenantTx("selection-a", func(tx *sql.Tx) error {
				_, err := tx.Exec(`UPDATE notification_rules SET event_types=$1::text[] WHERE id='rule'`, selection)
				return err
			})
			if err == nil {
				t.Fatal("invalid event selection accepted")
			}
		})
	}
	if err := tenantTx("selection-a", func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE notification_rules SET event_types=ARRAY['engagement.created','finding.created'] WHERE id='rule'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := tenantTx("selection-a", func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE notification_rules SET event_type='finding.ownership_changed',event_types=ARRAY['finding.ownership_changed','engagement.created'],all_teams=true WHERE id='rule'`)
		return err
	}); err == nil {
		t.Fatal("all_teams accepted an incompatible selected event")
	}
	publish := func(tenant, id string, capable bool) error {
		return tenantTx(tenant, func(tx *sql.Tx) error {
			if capable {
				if _, err := tx.Exec(`SELECT set_config('synapse.notification_rule_selector','explicit-v1',true)`); err != nil {
					return err
				}
			}
			_, err := tx.Exec(`INSERT INTO notification_events(tenant_id,id,event_type,source_kind,source_id,schema_version,occurred_at,data) VALUES($1,$2,'finding.created','selection-source',$2,1,now(),'{}')`, tenant, id)
			return err
		})
	}
	if err := publish("selection-a", "old-publisher", false); err == nil || !strings.Contains(err.Error(), "explicit event selection support") {
		t.Fatalf("old publisher=%v, want capability refusal", err)
	}
	if err := tenantTx("selection-a", func(tx *sql.Tx) error {
		var count int
		err := tx.QueryRow(`SELECT count(*) FROM notification_events WHERE id='old-publisher'`).Scan(&count)
		if err == nil && count != 0 {
			t.Fatal("refused publication persisted an event")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := publish("selection-a", "new-publisher", true); err != nil {
		t.Fatal(err)
	}
	if err := publish("selection-a", "old-after-new", false); err == nil || !strings.Contains(err.Error(), "explicit event selection support") {
		t.Fatalf("publisher capability leaked between transactions: %v", err)
	}
	if err := publish("selection-b", "foreign-publisher", false); err != nil {
		t.Fatalf("foreign tenant blocked by another tenant's selector: %v", err)
	}
	if err := tenantTx("selection-a", func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE notification_rules SET name='Legacy metadata update',revision=revision+1 WHERE id='rule'`)
		if err != nil {
			return err
		}
		var count int
		err = tx.QueryRow(`SELECT cardinality(event_types) FROM notification_rules WHERE id='rule'`).Scan(&count)
		if err == nil && count != 2 {
			t.Fatal("legacy metadata write narrowed selection")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 239); err == nil || !strings.Contains(err.Error(), "retire explicit multi-event") {
		t.Fatalf("unsafe rollback=%v", err)
	}
	if err := tenantTx("selection-a", func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE notification_rules SET event_types='{}' WHERE id='rule'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 239); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpTo(db, ".", 240); err != nil {
		t.Fatal(err)
	}
}
