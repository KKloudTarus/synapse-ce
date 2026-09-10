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
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	// t.Cleanup is LIFO. Register Close first so fixture deletion runs while the pool is still usable.
	t.Cleanup(pool.Close)

	repo := NewAdvisoryRepository(pool)
	id := "GHSA-" + randHex(t)
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), "DELETE FROM advisories WHERE id=$1", id); err != nil {
			t.Errorf("cleanup advisory %s: %v", id, err)
		}
	})

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

	// D1.7: the corpus reports its freshness (newest timestamp + count) after an upsert, so a stale owned
	// store can be warned. At least this advisory is present, so count >= 1 and the latest date is set.
	if latest, count, ferr := repo.AdvisoryFreshness(ctx); ferr != nil || count < 1 || latest.IsZero() {
		t.Fatalf("AdvisoryFreshness after upsert: latest=%v count=%d err=%v", latest, count, ferr)
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

// TestAdvisoryRepositoryUpsertPreservesEnrichment is the D1.2 corpus-clobber guard at the Postgres layer:
// the canonical materializer merges KEV/EPSS/PublicExploit onto an advisory's JSONB, then a bulk-feed re-sync
// via Upsert (which carries none) must NOT lower them. Base fields still refresh. Runs only under a real DB.
func TestAdvisoryRepositoryUpsertPreservesEnrichment(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	repo := NewAdvisoryRepository(pool)
	id := "CVE-" + randHex(t)
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), "DELETE FROM advisories WHERE id=$1", id); err != nil {
			t.Errorf("cleanup advisory %s: %v", id, err)
		}
	})

	// First write carries the risk enrichment the materializer would have merged in.
	enriched := advisory.Advisory{
		ID: id, Summary: "enriched", CVSSScore: 9.8,
		KEV: true, PublicExploit: true, EPSS: 0.88, EPSSPercentile: 0.97,
		Affected: []advisory.AffectedPackage{{Ecosystem: "npm", Package: "left-pad", FixedVersion: "1.3.0"}},
	}
	if err := repo.Upsert(ctx, enriched); err != nil {
		t.Fatalf("upsert enriched: %v", err)
	}

	// Bulk-feed re-sync: refreshed base fields, zero risk signals.
	bare := advisory.Advisory{
		ID: id, Summary: "refreshed base", CVSSScore: 9.8,
		Affected: []advisory.AffectedPackage{{Ecosystem: "npm", Package: "left-pad", FixedVersion: "1.3.0"}},
	}
	if err := repo.Upsert(ctx, bare); err != nil {
		t.Fatalf("re-upsert bare: %v", err)
	}

	got, err := repo.ByPackage(ctx, "npm", "left-pad")
	if err != nil {
		t.Fatalf("ByPackage: %v", err)
	}
	var found *advisory.Advisory
	for i := range got {
		if got[i].ID == id {
			found = &got[i]
		}
	}
	if found == nil {
		t.Fatalf("advisory %s not found after re-sync", id)
	}
	if !found.KEV || !found.PublicExploit || found.EPSS != 0.88 || found.EPSSPercentile != 0.97 {
		t.Errorf("risk enrichment clobbered: KEV=%v PublicExploit=%v EPSS=%v EPSSPct=%v",
			found.KEV, found.PublicExploit, found.EPSS, found.EPSSPercentile)
	}
	if found.Summary != "refreshed base" {
		t.Errorf("base summary not refreshed: got %q", found.Summary)
	}
}

// TestAdvisoryRepositoryUpsertConcurrentInsertKeepsEnrichment proves the advisory-lock race fix: two
// concurrent Upserts of the SAME new id (one enriched, one bare) must not clobber the enrichment, regardless
// of which commits first. A plain SELECT ... FOR UPDATE cannot lock a not-yet-inserted row, so without the
// pg_advisory_xact_lock both inserts could each see no prior row and the bare one could land last, dropping
// KEV/EPSS. Under the lock the two writers serialize and the enrichment survives. Runs only under a real DB.
func TestAdvisoryRepositoryUpsertConcurrentInsertKeepsEnrichment(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	repo := NewAdvisoryRepository(pool)
	// Repeat to exercise both commit orderings under contention.
	for i := 0; i < 8; i++ {
		id := "CVE-" + randHex(t)
		func() {
			t.Cleanup(func() {
				_, _ = pool.Exec(context.Background(), "DELETE FROM advisories WHERE id=$1", id)
			})
			enriched := advisory.Advisory{
				ID: id, Summary: "enriched", CVSSScore: 9.8, KEV: true, EPSS: 0.9,
				Affected: []advisory.AffectedPackage{{Ecosystem: "npm", Package: "left-pad", FixedVersion: "1.3.0"}},
			}
			bare := advisory.Advisory{
				ID: id, Summary: "bare", CVSSScore: 9.8,
				Affected: []advisory.AffectedPackage{{Ecosystem: "npm", Package: "left-pad", FixedVersion: "1.3.0"}},
			}
			start := make(chan struct{})
			done := make(chan error, 2)
			go func() { <-start; done <- repo.Upsert(ctx, enriched) }()
			go func() { <-start; done <- repo.Upsert(ctx, bare) }()
			close(start)
			for j := 0; j < 2; j++ {
				if err := <-done; err != nil {
					t.Fatalf("concurrent upsert: %v", err)
				}
			}
			got, err := repo.ByPackage(ctx, "npm", "left-pad")
			if err != nil {
				t.Fatalf("ByPackage: %v", err)
			}
			var found *advisory.Advisory
			for k := range got {
				if got[k].ID == id {
					found = &got[k]
				}
			}
			if found == nil {
				t.Fatalf("advisory %s missing after concurrent upsert", id)
			}
			if !found.KEV || found.EPSS != 0.9 {
				t.Fatalf("enrichment lost to a concurrent bare insert (iter %d): KEV=%v EPSS=%v", i, found.KEV, found.EPSS)
			}
		}()
	}
}

// TestAdvisoryRepositoryAliasEdges exercises the D2.5 alias-edge query against a real DB (the ?| intersection
// is backed by the migration-0145 GIN index): a query by an alias id returns that advisory's full edge set
// and does not leak an unrelated advisory.
func TestAdvisoryRepositoryAliasEdges(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("set SYNAPSE_TEST_DB_DSN to run the postgres integration test")
	}
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	repo := NewAdvisoryRepository(pool)

	id1 := "CVE-" + randHex(t)
	id2 := "CVE-" + randHex(t)
	aliasA := "GHSA-" + randHex(t)
	aliasB := "GHSA-" + randHex(t)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM advisories WHERE id = ANY($1)", []string{id1, id2})
	})
	if err := repo.Upsert(ctx, advisory.Advisory{ID: id1, Aliases: []string{aliasA, "OSV-" + randHex(t)}}); err != nil {
		t.Fatalf("upsert id1: %v", err)
	}
	if err := repo.Upsert(ctx, advisory.Advisory{ID: id2, Aliases: []string{aliasB}}); err != nil {
		t.Fatalf("upsert id2: %v", err)
	}

	edges, err := repo.AdvisoryAliasEdges(ctx, []string{aliasA})
	if err != nil {
		t.Fatalf("AdvisoryAliasEdges: %v", err)
	}
	var sawAliasA, leakedB bool
	for _, e := range edges {
		if e.AliasID == aliasA && e.CanonicalID == id1 {
			sawAliasA = true
		}
		if e.CanonicalID == id2 {
			leakedB = true
		}
	}
	if !sawAliasA {
		t.Errorf("query by %s must return its edge to %s; got %+v", aliasA, id1, edges)
	}
	if leakedB {
		t.Errorf("unrelated advisory %s must not be returned for %s", id2, aliasA)
	}
	if e, _ := repo.AdvisoryAliasEdges(ctx, nil); len(e) != 0 {
		t.Errorf("empty ids must return no edges, got %+v", e)
	}
}
