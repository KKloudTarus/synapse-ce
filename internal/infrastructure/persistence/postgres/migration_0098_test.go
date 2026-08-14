package postgres

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/migrations"
)

func TestMigration0098AdvisoryEvaluationCheckpointConstraints(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() {
		if err := Migrate(context.Background(), dsn); err != nil {
			t.Errorf("restore migrations: %v", err)
		}
	})
	db, err := goose.OpenDBWithDriver("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownTo(db, ".", 97); err != nil {
		t.Fatalf("down to 0097: %v", err)
	}
	if err := goose.UpTo(db, ".", 98); err != nil {
		t.Fatalf("up 0098: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	var forced bool
	if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE relname='advisory_evaluation_checkpoints'`).Scan(&forced); err != nil || !forced {
		t.Fatalf("advisory_evaluation_checkpoints FORCE RLS=%v err=%v", forced, err)
	}
	var primaryKey, revisionCheck string
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='advisory_evaluation_checkpoints'::regclass AND contype='p'`).Scan(&primaryKey); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='advisory_evaluation_checkpoints'::regclass AND contype='c'`).Scan(&revisionCheck); err != nil {
		t.Fatal(err)
	}
	primaryKey = strings.ToLower(primaryKey)
	revisionCheck = strings.ToLower(revisionCheck)
	if !strings.Contains(primaryKey, "tenant_id") || !strings.Contains(primaryKey, "advisory_id") {
		t.Fatalf("checkpoint primary key=%s", primaryKey)
	}
	if !strings.Contains(revisionCheck, "evaluated_revision") || !strings.Contains(revisionCheck, "> 0") {
		t.Fatalf("checkpoint revision constraint=%s", revisionCheck)
	}
}
