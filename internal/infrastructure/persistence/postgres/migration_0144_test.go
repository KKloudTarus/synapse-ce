package postgres

import (
	"context"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0144EmptyRoundTrip(t *testing.T) {
	db, _ := newMigration0140DB(t)
	if err := goose.UpTo(db, ".", 144); err != nil {
		t.Fatalf("up to 0144: %v", err)
	}
	var requestTable, authorizationColumn bool
	if err := db.QueryRowContext(context.Background(), `SELECT to_regclass('public.assessment_cycle_api_requests') IS NOT NULL`).Scan(&requestTable); err != nil || !requestTable {
		t.Fatalf("assessment_cycle_api_requests exists=%v err=%v", requestTable, err)
	}
	if err := db.QueryRowContext(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema='public' AND table_name='engagements' AND column_name='requires_explicit_execution_authorization'
	)`).Scan(&authorizationColumn); err != nil || !authorizationColumn {
		t.Fatalf("execution authorization column exists=%v err=%v", authorizationColumn, err)
	}
	if err := goose.DownTo(db, ".", 143); err != nil {
		t.Fatalf("rollback to 0143: %v", err)
	}
	if err := db.QueryRowContext(context.Background(), `SELECT to_regclass('public.assessment_cycle_api_requests') IS NOT NULL`).Scan(&requestTable); err != nil || requestTable {
		t.Fatalf("assessment_cycle_api_requests after rollback exists=%v err=%v", requestTable, err)
	}
	if err := db.QueryRowContext(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema='public' AND table_name='engagements' AND column_name='requires_explicit_execution_authorization'
	)`).Scan(&authorizationColumn); err != nil || authorizationColumn {
		t.Fatalf("execution authorization column after rollback exists=%v err=%v", authorizationColumn, err)
	}
}
