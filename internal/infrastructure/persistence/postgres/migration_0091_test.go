package postgres

import (
	"context"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0091AdvisoryHistoryRoundTrip(t *testing.T) {
	dsn := isolatedMigrationAt(t, 91)
	ctx := context.Background()
	db := openLockedGooseDB(t, dsn)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 90); err != nil {
		t.Fatalf("down to 0090: %v", err)
	}
	if err := goose.UpTo(db, ".", 91); err != nil {
		t.Fatalf("up 0091: %v", err)
	}
	for _, table := range []string{"vulnerability_sync_runs", "advisory_observations", "advisory_aliases", "advisory_revisions"} {
		var exists bool
		if err := db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil || !exists {
			t.Fatalf("table %s exists=%v err=%v", table, exists, err)
		}
	}
}
