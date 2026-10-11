package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

// Main can have 0190 installed before this PR lands. Verify that the normal
// migration entry point advances such a database through the SIEM migrations.
func TestMigration0192SIEMAfterNotification0190(t *testing.T) {
	sharedDSN := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if sharedDSN == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	dsn := isolatedMigrationDSN(t, sharedDSN, "0192")
	// This database is isolated. Do not hold openLockedGooseDB's advisory lock:
	// MigrateLocked must acquire it below, as it does in production.
	db, err := goose.OpenDBWithDriver("pgx", dsnForMigrate(dsn))
	if err != nil {
		t.Fatalf("open goose database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("dialect: %v", err)
	}
	if err := goose.UpTo(db, ".", 190); err != nil {
		t.Fatalf("apply main through 0190: %v", err)
	}
	if err := MigrateLocked(context.Background(), dsn); err != nil {
		t.Fatalf("upgrade database with 0190 applied: %v", err)
	}
	version, err := goose.GetDBVersion(db)
	if err != nil || version < 194 {
		t.Fatalf("migration version = %d, err = %v; want at least 194", version, err)
	}
	for _, name := range []string{"siem_sinks", "siem_incident_capture", "siem_incident_pruned", "siem_audit_v2_keyset_idx"} {
		var present bool
		if err := db.QueryRow(`SELECT to_regclass($1) IS NOT NULL`, "public."+name).Scan(&present); err != nil || !present {
			t.Errorf("%s present = %v, err = %v", name, present, err)
		}
	}
}
