package postgres

import (
	"context"
	"testing"

	"github.com/pressly/goose/v3"
)

func TestMigration0146EmptyRoundTrip(t *testing.T) {
	db, _ := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 146); err != nil {
		t.Fatalf("up to 0145: %v", err)
	}
	if err := goose.DownTo(db, ".", 145); err != nil {
		t.Fatalf("rollback to 0144: %v", err)
	}
	var exists bool
	if err := db.QueryRowContext(context.Background(), `SELECT to_regclass('public.assessment_comparisons') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Fatalf("assessment comparisons after rollback exists=%v err=%v", exists, err)
	}
}
