package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestImportedFindingsDurabilityAndIsolation exercises migration 0064 and the repository against a real
// database, because the guarantees this table carries are DATABASE guarantees:
//
//   - the ingest's append-only audit entry claims N external results entered an engagement, which is
//     only true if the rows survive; the memory store cannot make that claim;
//   - provenance is immutable, enforced by a trigger rather than by the store's good behaviour;
//   - re-posting the same document is idempotent, enforced by a unique index rather than by a map;
//   - tenants are isolated by Row Level Security, not by the query's WHERE clause.
func TestImportedFindingsDurabilityAndIsolation(t *testing.T) {
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

	// The table opts into the shared RLS shape.
	var forced bool
	if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE relname='imported_findings'`).Scan(&forced); err != nil {
		t.Fatalf("relforcerowsecurity: %v", err)
	}
	if !forced {
		t.Fatal("imported_findings must FORCE row level security: the app connects as the table owner")
	}

	for _, tenant := range []string{"t-imp-a", "t-imp-b"} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$1) ON CONFLICT (id) DO NOTHING`, tenant); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM imported_findings WHERE tenant_id IN ('t-imp-a','t-imp-b')`)
	})

	repo := NewImportedFindingRepository(pool)
	now := time.Now().UTC().Truncate(time.Millisecond)
	build := func(id, tenant, rule string) importedfinding.ImportedFinding {
		return importedfinding.ImportedFinding{
			ID: shared.ID(id), TenantID: shared.ID(tenant), EngagementID: "eng-imp",
			Severity: shared.SeverityHigh, Title: "t", Message: "m",
			Location: importedfinding.Location{Path: "src/app.go", StartLine: 4},
			Provenance: importedfinding.Provenance{
				ToolName: "semgrep", ToolVersion: "1.2.3", RuleID: rule, SourceDigest: "digest-a",
				IngestedBy: "human:alice", IngestedAt: now,
			},
			Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
		}
	}

	stored, existing, err := repo.Save(ctx, "t-imp-a", []importedfinding.ImportedFinding{build("if-1", "t-imp-a", "rule.a")})
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if stored != 1 || existing != 0 {
		t.Fatalf("first save = (%d stored, %d existing), want (1, 0)", stored, existing)
	}

	// Idempotency is the database's answer: the same document, rule and location is a no-op, and the
	// accepted/deduplicated split the caller reports comes from the unique index rather than a guess.
	stored, existing, err = repo.Save(ctx, "t-imp-a", []importedfinding.ImportedFinding{build("if-2", "t-imp-a", "rule.a")})
	if err != nil {
		t.Fatalf("re-save: %v", err)
	}
	if stored != 0 || existing != 1 {
		t.Fatalf("re-save = (%d stored, %d existing), want (0, 1)", stored, existing)
	}

	// A batch containing an unattributable finding aborts WHOLE: no prefix survives, so a retry cannot
	// find a partial ingest that looks complete.
	bad := build("if-3", "t-imp-a", "rule.b")
	bad.Provenance.ToolVersion = ""
	if _, _, err := repo.Save(ctx, "t-imp-a", []importedfinding.ImportedFinding{build("if-4", "t-imp-a", "rule.c"), bad}); err == nil {
		t.Fatal("a batch with incomplete provenance must fail")
	}
	list, err := repo.ListByEngagement(ctx, "t-imp-a", "eng-imp")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("a failed batch must persist nothing: expected 1 finding, got %d", len(list))
	}

	// Provenance is immutable at the database level, not merely avoided by the store.
	if _, err := pool.Exec(ctx, `SELECT set_config('app.current_tenant','t-imp-a',false)`); err != nil {
		t.Fatalf("set tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE imported_findings SET tool_name='forged' WHERE id='if-1'`); err == nil {
		t.Fatal("an imported finding's provenance must not be editable in place")
	}
	if _, err := pool.Exec(ctx, `SELECT set_config('app.current_tenant','',false)`); err != nil {
		t.Fatalf("reset tenant: %v", err)
	}

	// Tenant isolation: another tenant sees neither the finding nor its ingest history.
	other, err := repo.ListByEngagement(ctx, "t-imp-b", "eng-imp")
	if err != nil {
		t.Fatalf("list other tenant: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("another tenant must see no imported findings, got %d", len(other))
	}
	mine, err := repo.ExistsDigest(ctx, "t-imp-a", "eng-imp", "digest-a")
	if err != nil {
		t.Fatalf("exists digest: %v", err)
	}
	if !mine {
		t.Fatal("the ingesting tenant must see its own document digest")
	}
	theirs, err := repo.ExistsDigest(ctx, "t-imp-b", "eng-imp", "digest-a")
	if err != nil {
		t.Fatalf("exists digest other tenant: %v", err)
	}
	if theirs {
		t.Fatal("another tenant must not observe this tenant's ingest history")
	}
}
