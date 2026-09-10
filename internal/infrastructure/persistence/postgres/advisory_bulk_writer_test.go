package postgres

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
)

// cleanupBulkAdvisory removes every row a bulk-writer test created from the shared, un-tenanted advisory
// tables, so an accumulating test DB does not break other tests that list sources or query a package. All
// such rows embed the test's unique randHex suffix in their advisory id or source id. Deleting the advisory
// cascades to its affects, aliases, revisions, and checkpoints (ON DELETE CASCADE); observations must go
// before their source (no cascade on that FK).
func cleanupBulkAdvisory(t *testing.T, pool *pgxpool.Pool, suffix string) {
	t.Helper()
	ctx := context.Background()
	for _, stmt := range []string{
		`DELETE FROM advisories WHERE id LIKE '%' || $1`,
		`DELETE FROM advisory_observations WHERE source_id LIKE '%' || $1`,
		`DELETE FROM vulnerability_sources WHERE id LIKE '%' || $1`,
	} {
		if _, err := pool.Exec(ctx, stmt, suffix); err != nil {
			t.Logf("cleanup %q: %v", stmt, err)
		}
	}
}

// TestMaterializingAdvisoryWriterUnionsCrossFeed proves EPIC #860 D1.2: the same advisory ingested from two
// bulk sources yields the UNION of their affected packages, and re-ingesting one source does not clobber the
// other's ranges. Before this change the flat Upsert did ON CONFLICT DO UPDATE SET data=EXCLUDED.data, so
// the second feed dropped the first feed's affected packages (last-writer-wins). Package names are
// per-run-unique so the shared (global, un-tenanted) advisories table is not polluted for other tests.
func TestMaterializingAdvisoryWriterUnionsCrossFeed(t *testing.T) {
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
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	suffix := randHex(t)
	t.Cleanup(func() { cleanupBulkAdvisory(t, pool, suffix) })
	id := "SYN-UNION-" + suffix // shared advisory identity both feeds observe
	npmPkg := "left-pad-" + suffix
	pyPkg := "django-" + suffix

	writerA, err := NewMaterializingAdvisoryWriter(ctx, pool, "feed-a-"+suffix, "feed A", "osv", nil)
	if err != nil {
		t.Fatalf("writer A: %v", err)
	}
	writerB, err := NewMaterializingAdvisoryWriter(ctx, pool, "feed-b-"+suffix, "feed B", "csaf", nil)
	if err != nil {
		t.Fatalf("writer B: %v", err)
	}

	// Feed A covers the npm package; feed B covers the PyPI package. A union must keep both.
	advA := advisory.Advisory{
		ID: id, Summary: "from feed A", CVSSScore: 7.5,
		Affected: []advisory.AffectedPackage{{
			Ecosystem: "npm", Package: npmPkg, FixedVersion: "1.0.0",
			Ranges: []advisory.Range{{Type: "SEMVER", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.0.0"}}}},
		}},
	}
	advB := advisory.Advisory{
		ID: id, Summary: "from feed B", CVSSScore: 9.1,
		Affected: []advisory.AffectedPackage{{
			Ecosystem: "PyPI", Package: pyPkg, FixedVersion: "2.0.0",
			Ranges: []advisory.Range{{Type: "SEMVER", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.0.0"}}}},
		}},
	}

	if err := writerA.Upsert(ctx, advA); err != nil {
		t.Fatalf("upsert A: %v", err)
	}
	if err := writerB.Upsert(ctx, advB); err != nil {
		t.Fatalf("upsert B: %v", err)
	}

	assertAffected := func(when string, wantNPM, wantPyPI bool) {
		t.Helper()
		canonical, err := NewAdvisoryMaterializer(pool).GetCanonical(ctx, id)
		if err != nil {
			t.Fatalf("%s: get canonical: %v", when, err)
		}
		var haveNPM, havePyPI bool
		for _, a := range canonical.Advisory.Affected {
			if a.Ecosystem == "npm" && a.Package == npmPkg {
				haveNPM = true
			}
			if a.Ecosystem == "PyPI" && a.Package == pyPkg {
				havePyPI = true
			}
		}
		if haveNPM != wantNPM || havePyPI != wantPyPI {
			t.Fatalf("%s: affected=%+v; npm=%v(want %v) pypi=%v(want %v)", when, canonical.Advisory.Affected, haveNPM, wantNPM, havePyPI, wantPyPI)
		}
	}

	// After both feeds: the union has BOTH packages; neither feed clobbered the other.
	assertAffected("after A+B", true, true)

	// Re-ingesting feed A (idempotent re-sync) must NOT drop feed B's range.
	if err := writerA.Upsert(ctx, advA); err != nil {
		t.Fatalf("re-upsert A: %v", err)
	}
	assertAffected("after A re-sync", true, true)

	// Strongest CVSS wins across feeds (9.1 from B, not 7.5 from A).
	canonical, err := NewAdvisoryMaterializer(pool).GetCanonical(ctx, id)
	if err != nil {
		t.Fatalf("final get canonical: %v", err)
	}
	if canonical.Advisory.CVSSScore != 9.1 {
		t.Fatalf("merged CVSS = %v, want strongest 9.1", canonical.Advisory.CVSSScore)
	}
}

// TestMaterializingAdvisoryWriterSameSourceNarrows proves that a re-ingest from the SAME source narrows that
// source's contribution (a feed that retracts a package takes effect), while a second source's ranges
// remain. This is the property the flat path preserved and the materializer must keep.
func TestMaterializingAdvisoryWriterSameSourceNarrows(t *testing.T) {
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
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	suffix := randHex(t)
	t.Cleanup(func() { cleanupBulkAdvisory(t, pool, suffix) })
	id := "SYN-NARROW-" + suffix
	pkgA1 := "a-pkg-" + suffix
	pkgA2 := "b-pkg-" + suffix
	pkgB := "c-pkg-" + suffix
	writerA, err := NewMaterializingAdvisoryWriter(ctx, pool, "narrow-a-"+suffix, "feed A", "osv", nil)
	if err != nil {
		t.Fatal(err)
	}
	writerB, err := NewMaterializingAdvisoryWriter(ctx, pool, "narrow-b-"+suffix, "feed B", "csaf", nil)
	if err != nil {
		t.Fatal(err)
	}

	aff := func(eco, pkg, fixed string) advisory.AffectedPackage {
		return advisory.AffectedPackage{Ecosystem: eco, Package: pkg, FixedVersion: fixed,
			Ranges: []advisory.Range{{Type: "SEMVER", Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}}}}
	}
	// Feed A initially covers two packages; feed B covers one.
	if err := writerA.Upsert(ctx, advisory.Advisory{ID: id, Affected: []advisory.AffectedPackage{aff("npm", pkgA1, "1.0.0"), aff("npm", pkgA2, "1.0.0")}}); err != nil {
		t.Fatal(err)
	}
	if err := writerB.Upsert(ctx, advisory.Advisory{ID: id, Affected: []advisory.AffectedPackage{aff("PyPI", pkgB, "1.0.0")}}); err != nil {
		t.Fatal(err)
	}
	// Feed A re-syncs, now retracting its second package (only the first remains from A).
	if err := writerA.Upsert(ctx, advisory.Advisory{ID: id, Affected: []advisory.AffectedPackage{aff("npm", pkgA1, "1.0.0")}}); err != nil {
		t.Fatal(err)
	}
	canonical, err := NewAdvisoryMaterializer(pool).GetCanonical(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, a := range canonical.Advisory.Affected {
		got[a.Ecosystem+"/"+a.Package] = true
	}
	// pkgA1 (A, kept) and pkgB (B, untouched) remain; pkgA2 (A, retracted) is gone.
	if !got["npm/"+pkgA1] || !got["PyPI/"+pkgB] || got["npm/"+pkgA2] {
		t.Fatalf("narrowing wrong: %+v", canonical.Advisory.Affected)
	}
}

// TestMaterializingAdvisoryWriterWithdrawn proves a withdrawn feed advisory is recorded as withdrawn so the
// canonical projection keeps it out of the matcher (a retracted advisory is a guaranteed false positive).
func TestMaterializingAdvisoryWriterWithdrawn(t *testing.T) {
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
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	suffix := randHex(t)
	t.Cleanup(func() { cleanupBulkAdvisory(t, pool, suffix) })
	id := "SYN-WD-" + suffix
	writer, err := NewMaterializingAdvisoryWriter(ctx, pool, "wd-"+suffix, "feed", "osv", nil)
	if err != nil {
		t.Fatal(err)
	}
	adv := advisory.Advisory{ID: id, Summary: "retracted", Withdrawn: true,
		Affected: []advisory.AffectedPackage{{Ecosystem: "npm", Package: "wd-pkg-" + suffix, FixedVersion: "1.0.0",
			Ranges: []advisory.Range{{Type: "SEMVER", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.0.0"}}}}}}}
	if err := writer.Upsert(ctx, adv); err != nil {
		t.Fatalf("upsert withdrawn: %v", err)
	}
	canonical, err := NewAdvisoryMaterializer(pool).GetCanonical(ctx, id)
	if err != nil {
		t.Fatalf("get canonical: %v", err)
	}
	if canonical.Status != advisory.StatusWithdrawn {
		t.Fatalf("status = %q, want withdrawn", canonical.Status)
	}
	if !canonical.Project().Withdrawn {
		t.Fatal("projection must mark the advisory withdrawn so the matcher skips it")
	}
}

// TestMaterializingAdvisoryWriterSkipsConflictAndContinues proves a per-record data conflict (an advisory
// carrying two distinct CVE identities, which advisory.Merge rejects) is SKIPPED, not fatal: onSkip fires,
// Upsert returns nil, and a later valid advisory still ingests. This restores the flat path's best-effort
// bulk semantics that a fatal per-record error would have regressed.
func TestMaterializingAdvisoryWriterSkipsConflictAndContinues(t *testing.T) {
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
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	suffix := randHex(t)
	t.Cleanup(func() { cleanupBulkAdvisory(t, pool, suffix) })
	var skipped []string
	writer, err := NewMaterializingAdvisoryWriter(ctx, pool, "conflict-"+suffix, "feed", "osv",
		func(id string, _ error) { skipped = append(skipped, id) })
	if err != nil {
		t.Fatal(err)
	}

	// An advisory with two distinct CVE identities is unmergeable; the writer must skip it, not abort.
	bad := advisory.Advisory{ID: "SYN-BAD-" + suffix, Aliases: []string{"CVE-2026-11100", "CVE-2026-22200"},
		Affected: []advisory.AffectedPackage{{Ecosystem: "npm", Package: "bad-" + suffix, FixedVersion: "1.0.0"}}}
	if err := writer.Upsert(ctx, bad); err != nil {
		t.Fatalf("conflicting advisory must be skipped, not fatal: %v", err)
	}
	if len(skipped) != 1 || skipped[0] != bad.ID {
		t.Fatalf("onSkip not called for the conflicting advisory: %v", skipped)
	}

	// A valid advisory after the skip still ingests.
	goodID := "SYN-GOOD-" + suffix
	good := advisory.Advisory{ID: goodID,
		Affected: []advisory.AffectedPackage{{Ecosystem: "npm", Package: "good-" + suffix, FixedVersion: "2.0.0",
			Ranges: []advisory.Range{{Type: "SEMVER", Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.0.0"}}}}}}}
	if err := writer.Upsert(ctx, good); err != nil {
		t.Fatalf("valid advisory after a skip must ingest: %v", err)
	}
	if _, err := NewAdvisoryMaterializer(pool).GetCanonical(ctx, goodID); err != nil {
		t.Fatalf("valid advisory not materialized: %v", err)
	}
}
