package postgres

import (
	"database/sql"
	"testing"
)

func TestMigration0182CanonicalAssigneeBackfillAndLegacyBridge(t *testing.T) {
	_, db := ownershipTestDatabase(t, 181, func(db *sql.DB) {
		for _, row := range []struct{ id, name, disabled string }{
			{"assignee-exact", "Exact", "false"}, {"assignee-bob", "Bob", "false"},
			{"assignee-alex-1", "Alex", "false"}, {"assignee-alex-2", "Alex", "false"},
			{"assignee-disabled", "Disabled", "true"},
		} {
			if _, err := db.Exec(`INSERT INTO users(id,name,role,api_key_hash,disabled,tenant_id) VALUES($1,$2,'consultant',$1,$3::boolean,'default')`, row.id, row.name, row.disabled); err != nil {
				t.Fatal(err)
			}
		}
		withMigrationTenant(t, db, "default", func(tx *sql.Tx) {
			if _, err := tx.Exec(`INSERT INTO engagements(id,tenant_id,name) VALUES('assignee-eng','default','Canonical test')`); err != nil {
				t.Fatal(err)
			}
			for _, row := range []struct{ id, label string }{{"f-exact", "assignee-exact"}, {"f-name", "Bob"}, {"f-ambiguous", "Alex"}, {"f-unmatched", "Nobody"}, {"f-disabled", "assignee-disabled"}} {
				if _, err := tx.Exec(`INSERT INTO findings(id,tenant_id,engagement_id,title,assignee) VALUES($1,'default','assignee-eng',$1,$2)`, row.id, row.label); err != nil {
					t.Fatal(err)
				}
			}
		})
	})
	requireMigrationRLS(t, db, "finding_assignee_backfill_review")
	for _, tc := range []struct{ id, want, reason string }{
		{"f-exact", "assignee-exact", ""}, {"f-name", "assignee-bob", ""},
		{"f-ambiguous", "", "ambiguous"}, {"f-unmatched", "", "unmatched"},
		{"f-disabled", "assignee-disabled", ""},
	} {
		withMigrationTenant(t, db, "default", func(tx *sql.Tx) {
			var got sql.NullString
			if err := tx.QueryRow(`SELECT assignee_user_id FROM findings WHERE id=$1`, tc.id).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got.String != tc.want {
				t.Fatalf("%s canonical = %q, want %q", tc.id, got.String, tc.want)
			}
			if tc.reason != "" {
				var reason string
				if err := tx.QueryRow(`SELECT reason FROM finding_assignee_backfill_review WHERE finding_id=$1`, tc.id).Scan(&reason); err != nil || reason != tc.reason {
					t.Fatalf("%s review = %q, %v", tc.id, reason, err)
				}
			}
		})
	}
	withMigrationTenant(t, db, "default", func(tx *sql.Tx) {
		if _, err := tx.Exec(`UPDATE findings SET assignee='Bob' WHERE id='f-exact'`); err != nil {
			t.Fatal(err)
		}
		var id sql.NullString
		if err := tx.QueryRow(`SELECT assignee_user_id FROM findings WHERE id='f-exact'`).Scan(&id); err != nil || id.Valid {
			t.Fatalf("legacy name write kept canonical: %q %v", id.String, err)
		}
		if _, err := tx.Exec(`UPDATE findings SET assignee='assignee-bob' WHERE id='f-exact'`); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(`SELECT assignee_user_id FROM findings WHERE id='f-exact'`).Scan(&id); err != nil || id.String != "assignee-bob" {
			t.Fatalf("legacy exact ID bridge: %q %v", id.String, err)
		}
		if _, err := tx.Exec(`UPDATE findings SET assignee='assignee-disabled' WHERE id='f-exact'`); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(`SELECT assignee_user_id FROM findings WHERE id='f-exact'`).Scan(&id); err != nil || id.Valid {
			t.Fatalf("legacy disabled ID bound new assignment: %q %v", id.String, err)
		}
	})
}
