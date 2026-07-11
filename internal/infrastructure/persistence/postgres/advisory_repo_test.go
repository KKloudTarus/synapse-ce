package postgres

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Integration test – runs only when SYNAPSE_TEST_DB_DSN points at a Postgres.
func TestAdvisoryRepository(t *testing.T) {
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
	defer pool.Close()

	repo := NewAdvisoryRepository(pool)
	id := "GHSA-" + randHex(t)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM advisories WHERE id=$1", id) })

	a := advisory.Advisory{
		ID: id, Aliases: []string{"CVE-2024-9"}, Summary: "rce", CVSSScore: 9.8,
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Affected: []advisory.AffectedPackage{{
			Ecosystem: "Go", Package: "github.com/foo/bar", FixedVersion: "1.2.0",
			Ranges:   []advisory.Range{{Type: "SEMVER", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.2.0"}}}},
			Versions: []string{"1.0.0", "1.1.0"},
		}, {
			Ecosystem: "npm", Package: "left-pad", FixedVersion: "1.3.0",
		}},
	}
	if err := repo.Upsert(ctx, a); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// round-trip: the full advisory decodes back from the JSONB blob, found via the affect index
	got, err := repo.ByPackage(ctx, "Go", "github.com/foo/bar")
	if err != nil || len(got) != 1 {
		t.Fatalf("ByPackage Go: %+v err=%v", got, err)
	}
	if got[0].ID != id || got[0].CVSSScore != 9.8 || len(got[0].Affected) != 2 ||
		got[0].Affected[0].Ranges[0].Events[1].Fixed != "1.2.0" {
		t.Fatalf("advisory did not round-trip through JSONB: %+v", got[0])
	}
	// indexed under the second affected package too
	if g, _ := repo.ByPackage(ctx, "npm", "left-pad"); len(g) != 1 || g[0].ID != id {
		t.Fatalf("npm key: %+v", g)
	}
	// an unaffected package returns nothing
	if g, _ := repo.ByPackage(ctx, "Go", "github.com/safe/pkg"); len(g) != 0 {
		t.Fatalf("unaffected package: %+v", g)
	}

	// re-sync with a changed affected set: the Go binding is retracted, only npm remains. The stale index
	// row must be gone (no phantom hit) and there must be no duplicate npm row.
	a.Affected = []advisory.AffectedPackage{{Ecosystem: "npm", Package: "left-pad", FixedVersion: "1.3.0"}}
	if err := repo.Upsert(ctx, a); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	if g, _ := repo.ByPackage(ctx, "Go", "github.com/foo/bar"); len(g) != 0 {
		t.Fatalf("retracted Go binding must no longer match, got %+v", g)
	}
	if g, _ := repo.ByPackage(ctx, "npm", "left-pad"); len(g) != 1 {
		t.Fatalf("npm key must match exactly once after re-sync, got %d", len(g))
	}

	// empty id is rejected (fail-closed)
	if err := repo.Upsert(ctx, advisory.Advisory{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty advisory id: want ErrValidation, got %v", err)
	}
}
