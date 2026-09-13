package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/pressly/goose/v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vex"
)

// TestMigration0173VEXStatements verifies migration 0173 creates the vex_statements table (the persisted
// imported-VEX store, #1064 part 2b) with tenant RLS enabled, and that down removes it.
func TestMigration0173VEXStatements(t *testing.T) {
	ctx := context.Background()
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.UpTo(db, ".", 173); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	tableExists := func() bool {
		var n int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM information_schema.tables WHERE table_name='vex_statements'`).Scan(&n); err != nil {
			t.Fatalf("query table: %v", err)
		}
		return n == 1
	}
	if !tableExists() {
		t.Fatal("vex_statements must exist after migration 0173")
	}
	// RLS must be enabled: an un-policed tenant table would leak statements across tenants.
	var rls bool
	if err := pool.QueryRow(ctx,
		`SELECT relrowsecurity FROM pg_class WHERE relname='vex_statements'`).Scan(&rls); err != nil {
		t.Fatalf("query rls: %v", err)
	}
	if !rls {
		t.Error("vex_statements must have row-level security enabled")
	}

	if err := goose.DownTo(db, ".", 172); err != nil {
		t.Fatalf("migrate down: %v", err)
	}
	if tableExists() {
		t.Fatal("vex_statements must be removed after down to 172")
	}
}

// TestVEXStatementRepositoryRoundTrip exercises the Postgres repository end to end against a real database:
// a batch persists, re-saving an identical assertion is idempotent, the read is oldest-first, and a
// different engagement/tenant is isolated.
func TestVEXStatementRepositoryRoundTrip(t *testing.T) {
	ctx := context.Background()
	db, dsn := newAssessmentMigrationDB(t)
	if err := goose.Up(db, "."); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	repo := NewVEXStatementRepository(pool)
	tenant := shared.ID("default") // seeded by migration 0058
	eng := shared.ID("eng-vex-1")
	t0 := time.Unix(1700000000, 0).UTC()

	s1 := vex.NewStoredStatement(vex.Statement{Vulnerability: "CVE-2024-0001", Products: []string{"pkg@1.0"}, Status: "not_affected", Justification: "vulnerable_code_not_present"}, "human:alice", t0)
	s2 := vex.NewStoredStatement(vex.Statement{Vulnerability: "CVE-2024-0002", Products: []string{"pkg2@2.0"}, Status: "fixed"}, "human:alice", t0.Add(time.Second))
	if err := repo.Save(ctx, tenant, eng, []vex.StoredStatement{s1, s2}); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Re-saving s1 (identical digest) must be idempotent.
	if err := repo.Save(ctx, tenant, eng, []vex.StoredStatement{s1}); err != nil {
		t.Fatalf("save idempotent: %v", err)
	}

	got, err := repo.ListByEngagement(ctx, tenant, eng)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 persisted statements (idempotent re-save), got %d", len(got))
	}
	// Oldest-first: s1 (t0) before s2 (t0+1s), and the faithful assertion round-tripped.
	if got[0].Advisory != "CVE-2024-0001" || got[1].Advisory != "CVE-2024-0002" {
		t.Errorf("statements must be oldest-first, got %q then %q", got[0].Advisory, got[1].Advisory)
	}
	if got[0].Statement.Status != "not_affected" || len(got[0].Statement.Products) != 1 || got[0].Statement.Products[0] != "pkg@1.0" {
		t.Errorf("the faithful assertion must round-trip, got %+v", got[0].Statement)
	}

	// A different engagement is isolated.
	other, err := repo.ListByEngagement(ctx, tenant, shared.ID("eng-vex-other"))
	if err != nil {
		t.Fatalf("list other: %v", err)
	}
	if len(other) != 0 {
		t.Errorf("a different engagement must see no statements, got %d", len(other))
	}
}
