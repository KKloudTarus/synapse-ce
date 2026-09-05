package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
)

// openLockedGooseDB opens a goose handle for a migration test and holds the migration advisory lock
// for the duration of that test on a SEPARATE connection.
//
// The migration tests roll the SHARED test database down to a version and back up, so while one is
// running the schema does not match goose's recorded version. Another package migrating the same
// database at that moment fails on whatever object the rollback left behind, for example
// `relation "imported_findings_id_tenant_engagement_unique" already exists` from 0070. go test runs
// packages concurrently, so that is a real collision rather than a hypothetical one. MigrateLocked
// takes the same lock, which makes the two mutually exclusive.
//
// The lock deliberately lives on its own handle. Holding it on the goose handle would mean capping
// that handle at a single connection, and a migration test that has rows open while issuing another
// statement then waits forever for a connection that its own cursor is holding.
//
// A test that holds this lock must migrate with the UNLOCKED Migrate, including from a cleanup.
// Cleanups run LIFO, so a restore-to-HEAD cleanup registered after this helper runs while the lock
// is still held; calling MigrateLocked there waits forever on a lock the same test owns.
func openLockedGooseDB(t *testing.T, dsn string) *sql.DB {
	t.Helper()

	lockDB, err := sql.Open("pgx", dsnForMigrate(dsn))
	if err != nil {
		t.Fatalf("open migration lock connection: %v", err)
	}
	lockDB.SetMaxOpenConns(1)
	lockDB.SetMaxIdleConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := lockDB.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey()); err != nil {
		_ = lockDB.Close()
		t.Fatalf("acquire migration advisory lock: %v", err)
	}
	// Closing the connection releases the session lock, so this cleanup is the release. It runs
	// after the caller's own deferred close of the goose handle, which is independent of it.
	t.Cleanup(func() { _ = lockDB.Close() })

	db, err := goose.OpenDBWithDriver("pgx", dsnForMigrate(dsn))
	if err != nil {
		t.Fatalf("open goose db: %v", err)
	}
	return db
}
