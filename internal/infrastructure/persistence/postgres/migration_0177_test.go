package postgres

import (
	"context"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0177ProjectPRDecoration(t *testing.T) {
	ctx := context.Background()
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 177); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	var (
		dataType   string
		nullable   string
		defaultVal *string
	)
	err = pool.QueryRow(ctx, `SELECT data_type, is_nullable, column_default FROM information_schema.columns
		WHERE table_name='projects' AND column_name='decorate_pull_requests'`).Scan(&dataType, &nullable, &defaultVal)
	if err != nil {
		t.Fatalf("decorate_pull_requests column must exist after 0177: %v", err)
	}
	if dataType != "boolean" {
		t.Fatalf("data_type = %q, want boolean", dataType)
	}
	if nullable != "NO" {
		t.Fatalf("is_nullable = %q, want NO (fail-closed default)", nullable)
	}
	if defaultVal == nil || *defaultVal != "false" {
		t.Fatalf("column_default = %v, want false", defaultVal)
	}

	if err := goose.DownTo(db, ".", 176); err != nil {
		t.Fatalf("migrate down: %v", err)
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_name='projects' AND column_name='decorate_pull_requests')`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("decorate_pull_requests must be dropped by the down migration")
	}
}
