package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func newAssessmentMigrationDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	sharedDSN := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if sharedDSN == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	dsn := isolatedAssessmentMigrationDSN(t, sharedDSN)
	db, err := goose.OpenDBWithDriver("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	return db, dsn
}

func isolatedAssessmentMigrationDSN(t *testing.T, sharedDSN string) string {
	t.Helper()
	u, err := url.Parse(sharedDSN)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatalf("parse PostgreSQL test DSN: %v", err)
	}
	name := fmt.Sprintf("synapse_assessment_migration_%d", time.Now().UnixNano())
	isolated := *u
	isolated.Path = "/" + name
	isolated.RawPath = ""
	admin, err := Connect(context.Background(), sharedDSN)
	if err != nil {
		t.Fatalf("connect PostgreSQL admin database: %v", err)
	}
	quotedName := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(context.Background(), "CREATE DATABASE "+quotedName); err != nil {
		admin.Close()
		t.Fatalf("create isolated migration database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = admin.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1`, name)
		if _, err := admin.Exec(ctx, "DROP DATABASE "+quotedName); err != nil {
			t.Errorf("drop isolated migration database: %v", err)
		}
		admin.Close()
	})
	return isolated.String()
}
