package postgres

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func ownershipTestDatabase(t *testing.T, base int64, before func(*sql.DB)) (*pgxpool.Pool, *sql.DB) {
	t.Helper()
	isolated := newIsolatedMigrationDB(t, 164, base)
	if before != nil {
		before(isolated.db)
	}
	var database, role string
	if err := isolated.db.QueryRow(`SELECT current_database(),current_user`).Scan(&database, &role); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(os.Getenv("SYNAPSE_TEST_DB_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + database
	u.RawPath = ""
	u.User = url.UserPassword(role, "migration-test-password")
	// Exercise the real startup entry point and its complete embedded migration set.
	if err := Migrate(context.Background(), u.String()); err != nil {
		t.Fatalf("startup migrate: %v", err)
	}
	admin, err := Connect(context.Background(), os.Getenv("SYNAPSE_TEST_DB_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	runtimeRole := role + "_runtime"
	quoted := pgx.Identifier{runtimeRole}.Sanitize()
	if _, err := admin.Exec(context.Background(), "CREATE ROLE "+quoted+" LOGIN PASSWORD 'ownership-runtime-test' NOSUPERUSER NOBYPASSRLS"); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, grant := range []string{"ALL TABLES IN SCHEMA public", "ALL SEQUENCES IN SCHEMA public", "SCHEMA public"} {
			if _, err := isolated.db.Exec("REVOKE ALL PRIVILEGES ON " + grant + " FROM " + quoted); err != nil {
				t.Error(err)
			}
		}
		if _, err := admin.Exec(context.Background(), "DROP ROLE "+quoted); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	for _, grant := range []string{"SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public", "USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public", "USAGE ON SCHEMA public"} {
		if _, err := isolated.db.Exec("GRANT " + grant + " TO " + quoted); err != nil {
			t.Fatal(err)
		}
	}
	u.User = url.UserPassword(runtimeRole, "ownership-runtime-test")
	pool, err := pgxpool.New(context.Background(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := CheckRLSRuntimeRole(context.Background(), pool); err != nil {
		t.Fatalf("test must use real RLS: %v", err)
	}
	return pool, isolated.db
}

func TestOwnershipMigrationVersionsUnique(t *testing.T) {
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int64]string{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			t.Fatalf("unnumbered migration %s", entry.Name())
		}
		n, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if prior, ok := seen[n]; ok {
			t.Fatalf("duplicate goose version %d: %s and %s", n, prior, entry.Name())
		}
		seen[n] = entry.Name()
	}
}

func TestMigration0168OwnershipFresh(t *testing.T) {
	_, db := ownershipTestDatabase(t, 0, nil)
	for _, table := range []string{"ownership_teams", "ownership_memberships", "ownership_mappings", "ownership_asset_mappings", "ownership_snapshots", "ownership_policies", "ownership_policy_versions", "ownership_policy_team_refs", "ownership_policy_project_refs", "ownership_policy_asset_refs", "ownership_assignments", "ownership_decisions", "ownership_intents", "ownership_runs", "ownership_run_items"} {
		requireMigrationTable(t, db, table, true)
		requireMigrationRLS(t, db, table)
	}
	requireMigrationIndexes(t, db, "ownership_assignments_inbox", "ownership_assignments_assignee", "ownership_assignments_resolution", "ownership_decisions_history", "ownership_intents_pending")
}

func TestMigration0168OwnershipUpgradePreservesLegacy(t *testing.T) {
	_, db := ownershipTestDatabase(t, 163, func(db *sql.DB) {
		if _, err := db.Exec(`INSERT INTO users(id,name,role,api_key_hash,tenant_id) VALUES('legacy-bootstrap','Admin','admin','ownership-upgrade-key','')`); err != nil {
			t.Fatal(err)
		}
		withMigrationTenant(t, db, "default", func(tx *sql.Tx) {
			if _, err := tx.Exec(`INSERT INTO engagements(id,tenant_id,name) VALUES('upgrade-e','default','Legacy'); INSERT INTO findings(id,tenant_id,engagement_id,title,assignee) VALUES('upgrade-f','default','upgrade-e','Legacy finding','Old free-text owner')`); err != nil {
				t.Fatal(err)
			}
		})
	})
	var raw, normalized string
	if err := db.QueryRow(`SELECT tenant_id,ownership_tenant_id FROM users WHERE id='legacy-bootstrap'`).Scan(&raw, &normalized); err != nil || raw != "" || normalized != "default" {
		t.Fatalf("legacy user changed: %q %q %v", raw, normalized, err)
	}
	withMigrationTenant(t, db, "default", func(tx *sql.Tx) {
		var assignee string
		var count int
		if err := tx.QueryRow(`SELECT assignee FROM findings WHERE id='upgrade-f'`).Scan(&assignee); err != nil || assignee != "Old free-text owner" {
			t.Fatalf("legacy assignee=%s %v", assignee, err)
		}
		if err := tx.QueryRow(`SELECT count(*) FROM ownership_assignments`).Scan(&count); err != nil || count != 0 {
			t.Fatalf("migration reassigned findings: %d %v", count, err)
		}
		if _, err := tx.Exec(`INSERT INTO ownership_teams(tenant_id,id,slug,name,revision,created_at,updated_at) VALUES('default','default-team','default-team','Default',1,now(),now()); INSERT INTO ownership_memberships(tenant_id,team_id,user_id,created_at) VALUES('default','default-team','legacy-bootstrap',now())`); err != nil {
			t.Fatalf("default tenant FK: %v", err)
		}
	})
	if err := goose.DownTo(db, ".", 163); err != nil {
		t.Fatalf("down: %v", err)
	}
	requireMigrationTable(t, db, "ownership_teams", false)
	if err := db.QueryRow(`SELECT tenant_id FROM users WHERE id='legacy-bootstrap'`).Scan(&raw); err != nil || raw != "" {
		t.Fatalf("rollback changed user: %q %v", raw, err)
	}
}
