package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

type isolatedMigrationDB struct {
	db *sql.DB
}

// newIsolatedMigrationDB creates a database and non-superuser owner dedicated to one migration test.
// Unlike shared-DSN migration tests, it can safely exercise Goose rollback paths without changing the
// caller's configured test database.
func newIsolatedMigrationDB(t *testing.T, migration int, baseVersion int64) isolatedMigrationDB {
	t.Helper()

	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the PostgreSQL migration integration test")
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatalf("parse PostgreSQL test DSN: %v", err)
	}

	ctx := context.Background()
	admin, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect test database administrator: %v", err)
	}
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	role := fmt.Sprintf("migration_%d_%s", migration, id)
	database := fmt.Sprintf("synapse_migration_%d_%s", migration, id)
	quotedRole := pgx.Identifier{role}.Sanitize()
	quotedDatabase := pgx.Identifier{database}.Sanitize()
	const password = "migration-test-password"
	if _, err := admin.Exec(ctx, "CREATE ROLE "+quotedRole+" LOGIN PASSWORD '"+password+"' NOSUPERUSER NOBYPASSRLS"); err != nil {
		admin.Close()
		t.Fatalf("create isolated migration owner: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quotedDatabase+" OWNER "+quotedRole); err != nil {
		_, _ = admin.Exec(ctx, "DROP ROLE "+quotedRole)
		admin.Close()
		t.Fatalf("create isolated migration database: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = admin.Exec(cleanupCtx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1`, database)
		if _, err := admin.Exec(cleanupCtx, "DROP DATABASE "+quotedDatabase); err != nil {
			t.Errorf("drop isolated migration database: %v", err)
		}
		if _, err := admin.Exec(cleanupCtx, "DROP ROLE "+quotedRole); err != nil {
			t.Errorf("drop isolated migration owner: %v", err)
		}
		admin.Close()
	})

	isolated := *u
	isolated.Path = "/" + database
	isolated.RawPath = ""
	isolated.User = url.UserPassword(role, password)
	db, err := sql.Open("pgx", dsnForMigrate(isolated.String()))
	if err != nil {
		t.Fatalf("open isolated migration database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpTo(db, ".", baseVersion); err != nil {
		t.Fatalf("migrate isolated database to %04d: %v", baseVersion, err)
	}
	return isolatedMigrationDB{db: db}
}

func withMigrationTenant(t *testing.T, db *sql.DB, tenant string, fn func(*sql.Tx)) {
	t.Helper()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tenant transaction: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant',$1,true)`, tenant); err != nil {
		t.Fatalf("scope tenant transaction: %v", err)
	}
	fn(tx)
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tenant transaction: %v", err)
	}
}

func requireMigrationWriteRejected(t *testing.T, tx *sql.Tx, query string, args ...any) {
	t.Helper()
	if _, err := tx.Exec(`SAVEPOINT expected_migration_rejection`); err != nil {
		t.Fatalf("create rejection savepoint: %v", err)
	}
	if _, err := tx.Exec(query, args...); err == nil {
		t.Fatalf("migration accepted invalid write: %s", query)
	}
	if _, err := tx.Exec(`ROLLBACK TO SAVEPOINT expected_migration_rejection`); err != nil {
		t.Fatalf("roll back rejected write: %v", err)
	}
}

func requireMigrationRLS(t *testing.T, db *sql.DB, table string) {
	t.Helper()
	var enabled, forced bool
	if err := db.QueryRow(`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid=$1::regclass`, table).Scan(&enabled, &forced); err != nil {
		t.Fatalf("inspect RLS for %s: %v", table, err)
	}
	if !enabled || !forced {
		t.Fatalf("RLS for %s enabled/forced=%t/%t, want true/true", table, enabled, forced)
	}
}

func requireMigrationIndexes(t *testing.T, db *sql.DB, indexes ...string) {
	t.Helper()
	for _, index := range indexes {
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname=$1)`, index).Scan(&exists); err != nil {
			t.Fatalf("inspect index %s: %v", index, err)
		}
		if !exists {
			t.Fatalf("migration did not create index %s", index)
		}
	}
}

func migrationPolicies(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT policyname FROM pg_policies WHERE schemaname='public' AND tablename=$1`, table)
	if err != nil {
		t.Fatalf("list policies for %s: %v", table, err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan policy for %s: %v", table, err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate policies for %s: %v", table, err)
	}
	sort.Strings(names)
	return names
}

func requireMigrationPolicies(t *testing.T, db *sql.DB, table string, want ...string) {
	t.Helper()
	got := migrationPolicies(t, db, table)
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("policies for %s = %v, want %v", table, got, want)
	}
}

func requireMigrationTable(t *testing.T, db *sql.DB, table string, want bool) {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1)`, table).Scan(&exists); err != nil {
		t.Fatalf("inspect table %s: %v", table, err)
	}
	if exists != want {
		t.Fatalf("table %s exists=%t, want %t", table, exists, want)
	}
}
