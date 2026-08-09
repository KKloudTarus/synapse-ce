package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestMigration0067PinsReviewEvidenceToOneTenant verifies the properties that
// cannot be supplied by the use-case layer: forced RLS and composite parent
// references for the finding and sealed evidence reviewed by a human.
func TestMigration0067PinsReviewEvidenceToOneTenant(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	var forced bool
	if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE relname='ai_triage_reviews'`).Scan(&forced); err != nil {
		t.Fatalf("read RLS state: %v", err)
	}
	if !forced {
		t.Fatal("ai_triage_reviews must FORCE row level security")
	}

	rows, err := pool.Query(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='ai_triage_reviews'::regclass`)
	if err != nil {
		t.Fatalf("read constraints: %v", err)
	}
	defer rows.Close()
	var definitions []string
	for rows.Next() {
		var definition string
		if err := rows.Scan(&definition); err != nil {
			t.Fatalf("scan constraint: %v", err)
		}
		definitions = append(definitions, strings.ToLower(definition))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate constraints: %v", err)
	}
	joined := strings.Join(definitions, "\n")
	for _, required := range []string{
		"foreign key (tenant_id, engagement_id, finding_id)",
		"foreign key (tenant_id, engagement_id, evidence_ref)",
		"review_required",
		"not gate_exempt",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("migration is missing %q; constraints:\n%s", required, joined)
		}
	}
}
