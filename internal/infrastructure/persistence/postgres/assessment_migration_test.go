package postgres

import (
	"database/sql"
	"os"
	"testing"

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
	return isolatedMigrationDSN(t, sharedDSN, "assessment")
}
