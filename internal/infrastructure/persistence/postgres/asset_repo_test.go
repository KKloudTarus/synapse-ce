package postgres

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"slices"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestAssetRepository(t *testing.T) {
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
	t.Cleanup(func() { pool.Close() })

	// Seed two tenants (FK target). Clean asset rows then tenants (FK order) at the end.
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ('ta','A'),('tb','B') ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatalf("seed tenants: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM fleet_asset_edges WHERE tenant_id IN ('ta','tb')`)
		_, _ = pool.Exec(bg, `DELETE FROM fleet_business_services WHERE tenant_id IN ('ta','tb')`)
		_, _ = pool.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id IN ('ta','tb')`)
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id IN ('ta','tb')`)
	})

	repo := NewAssetRepository(pool)
	now := time.Now().UTC().Truncate(time.Second)

	// Roundtrip.
	a, err := asset.New("as1", "ta", asset.KindImage, "sha256:x", "img", map[string]string{"os": "linux"}, now)
	if err != nil {
		t.Fatalf("new asset: %v", err)
	}
	if err := repo.UpsertAsset(ctx, a); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := repo.GetAssetByKey(ctx, "ta", asset.KindImage, "sha256:x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != "as1" || got.Name != "img" || got.Attributes["os"] != "linux" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}

	// Idempotent upsert: same natural key -> one row, id preserved.
	if err := repo.UpsertAsset(ctx, a); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	list, err := repo.ListAssets(ctx, "ta")
	if err != nil {
		t.Fatalf("list ta: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("idempotent upsert should keep one row, got %d", len(list))
	}

	// Not found.
	if _, err := repo.GetAssetByKey(ctx, "ta", asset.KindImage, "sha256:missing"); err == nil {
		t.Fatalf("expected ErrNotFound for missing key")
	}

	// Query-level tenant scoping: tenant tb's asset is not in ta's list.
	b, _ := asset.New("as2", "tb", asset.KindImage, "sha256:y", "img2", nil, now)
	if err := repo.UpsertAsset(ctx, b); err != nil {
		t.Fatalf("upsert tb: %v", err)
	}
	list, err = repo.ListAssets(ctx, "ta")
	if err != nil {
		t.Fatalf("list ta again: %v", err)
	}
	if len(list) != 1 || list[0].TenantID != "ta" {
		t.Fatalf("tenant scoping failed: %+v", list)
	}

	// A second asset in tenant ta so the edge references two assets in the SAME tenant (the
	// composite FK forbids cross-tenant edges).
	a3, _ := asset.New("as3", "ta", asset.KindWorkload, "wl-1", "wl", nil, now)
	if err := repo.UpsertAsset(ctx, a3); err != nil {
		t.Fatalf("upsert as3: %v", err)
	}

	// Edge roundtrip + idempotency (ON CONFLICT DO NOTHING).
	e, _ := asset.NewEdge("ta", "as1", "as3", asset.EdgeRuns, "obs1", asset.EdgeObserved)
	if err := repo.UpsertEdge(ctx, e); err != nil {
		t.Fatalf("upsert edge: %v", err)
	}
	if err := repo.UpsertEdge(ctx, e); err != nil {
		t.Fatalf("re-upsert edge: %v", err)
	}
	edges, err := repo.ListEdges(ctx, "ta")
	if err != nil {
		t.Fatalf("list edges: %v", err)
	}
	if len(edges) != 1 || edges[0].Kind != asset.EdgeRuns || edges[0].Confidence != asset.EdgeObserved {
		t.Fatalf("expected one observed runs edge, got %+v", edges)
	}

	// Empty tenant is rejected by the domain before it ever reaches the DB.
	if _, err := asset.New("z", "", asset.KindHost, "h", "h", nil, now); err == nil {
		t.Fatalf("empty tenant asset should be rejected by domain")
	}
	_ = shared.ID("")
}

// CountBusinessAssetsByCriticality answers from a database aggregate rather than by listing, so it
// needs a real Postgres to prove the SQL and the tenant scoping under RLS.
func TestCountBusinessAssetsByCriticality(t *testing.T) {
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
	t.Cleanup(func() { pool.Close() })

	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ('tcount-a','A'),('tcount-b','B') ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatalf("seed tenants: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM fleet_business_services WHERE tenant_id IN ('tcount-a','tcount-b')`)
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id IN ('tcount-a','tcount-b')`)
	})

	repo := NewAssetRepository(pool)
	now := time.Now().UTC().Truncate(time.Second)
	seed := func(tenant, key string, criticality asset.Criticality) {
		t.Helper()
		ba, err := asset.NewBusinessAsset(shared.ID(key), shared.ID(tenant), key, "Service", "", asset.BusinessAssetApplication, criticality, "platform-team", nil, "operator", now)
		if err != nil {
			t.Fatalf("new business asset: %v", err)
		}
		if err := repo.CreateBusinessAsset(ctx, ba); err != nil {
			t.Fatalf("create business asset: %v", err)
		}
	}

	for i := range 7 {
		seed("tcount-a", fmt.Sprintf("a-crit-%d", i), asset.CriticalityCritical)
	}
	for i := range 3 {
		seed("tcount-a", fmt.Sprintf("a-low-%d", i), asset.CriticalityLow)
	}
	seed("tcount-b", "b-crit-0", asset.CriticalityCritical)

	counts, err := repo.CountBusinessAssetsByCriticality(ctx, "tcount-a")
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if got := counts[asset.CriticalityCritical]; got != 7 {
		t.Fatalf("critical = %d, want 7", got)
	}
	if got := counts[asset.CriticalityLow]; got != 3 {
		t.Fatalf("low = %d, want 3", got)
	}
	// A criticality with no rows is absent rather than zero, and another tenant's rows never leak.
	if _, present := counts[asset.CriticalityHigh]; present {
		t.Fatalf("high should be absent, got %v", counts)
	}
	other, err := repo.CountBusinessAssetsByCriticality(ctx, "tcount-b")
	if err != nil {
		t.Fatalf("count other tenant: %v", err)
	}
	if got := other[asset.CriticalityCritical]; got != 1 {
		t.Fatalf("tenant-b critical = %d, want 1", got)
	}
}

// The SQL filter must mean exactly what the in-memory twin means, or the dashboard shows different
// results depending on which store is configured.
func TestListBusinessAssetsPageFilterSemantics(t *testing.T) {
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
	t.Cleanup(func() { pool.Close() })

	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ('tpage-a','A'),('tpage-b','B') ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatalf("seed tenants: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM fleet_business_services WHERE tenant_id IN ('tpage-a','tpage-b')`)
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id IN ('tpage-a','tpage-b')`)
	})

	repo := NewAssetRepository(pool)
	now := time.Now().UTC().Truncate(time.Second)
	seed := func(tenant, key, name, owner string, criticality asset.Criticality) {
		t.Helper()
		ba, err := asset.NewBusinessAsset(shared.ID("id-"+key), shared.ID(tenant), key, name, "", asset.BusinessAssetApplication, criticality, owner, nil, "operator", now)
		if err != nil {
			t.Fatalf("new business asset: %v", err)
		}
		if err := repo.CreateBusinessAsset(ctx, ba); err != nil {
			t.Fatalf("create business asset: %v", err)
		}
	}

	seed("tpage-a", "api-gateway", "Edge Gateway", "platform-team", asset.CriticalityCritical)
	seed("tpage-a", "billing", "Billing Service", "payments-team", asset.CriticalityHigh)
	seed("tpage-a", "catalog", "Product Catalog", "platform-team", asset.CriticalityLow)
	seed("tpage-b", "other", "Other Tenant", "platform-team", asset.CriticalityCritical)

	// Text is matched case-insensitively across "<key> <name>" joined by a space, so a substring
	// spanning the join matches ("api-gateway" + " " + "Edge Gateway" contains "gateway edge")...
	items, total, err := repo.ListBusinessAssetsPage(ctx, "tpage-a", ports.BusinessAssetQuery{Query: "GATEWAY EDGE", Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Key != "api-gateway" {
		t.Fatalf("join-spanning substring total=%d items=%d, want the api-gateway row", total, len(items))
	}
	// ...while terms from two different rows match neither, because this is a substring test and
	// not a word-set test. The in-memory twin does strings.Contains over the same joined value.
	if _, total, err = repo.ListBusinessAssetsPage(ctx, "tpage-a", ports.BusinessAssetQuery{Query: "gateway billing", Limit: 10}); err != nil || total != 0 {
		t.Fatalf("cross-row terms matched %d rows (err %v), want 0", total, err)
	}
	items, total, err = repo.ListBusinessAssetsPage(ctx, "tpage-a", ports.BusinessAssetQuery{Query: "Product", Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Key != "catalog" {
		t.Fatalf("text filter total=%d items=%d, want the catalog row", total, len(items))
	}

	// A wildcard in the caller's text is a literal, not a pattern.
	if _, total, err = repo.ListBusinessAssetsPage(ctx, "tpage-a", ports.BusinessAssetQuery{Query: "%", Limit: 10}); err != nil || total != 0 {
		t.Fatalf("percent matched %d rows (err %v), want 0: caller text must not be a LIKE pattern", total, err)
	}
	if _, total, err = repo.ListBusinessAssetsPage(ctx, "tpage-a", ports.BusinessAssetQuery{Query: "_", Limit: 10}); err != nil || total != 0 {
		t.Fatalf("underscore matched %d rows (err %v), want 0", total, err)
	}

	// Owner is a case-insensitive substring; the typed filters are exact.
	if _, total, err = repo.ListBusinessAssetsPage(ctx, "tpage-a", ports.BusinessAssetQuery{Owner: "PLATFORM", Limit: 10}); err != nil || total != 2 {
		t.Fatalf("owner filter total=%d err=%v, want 2", total, err)
	}
	if _, total, err = repo.ListBusinessAssetsPage(ctx, "tpage-a", ports.BusinessAssetQuery{Criticality: asset.CriticalityHigh, Limit: 10}); err != nil || total != 1 {
		t.Fatalf("criticality filter total=%d err=%v, want 1", total, err)
	}

	// The total counts every match, not the page, and paging follows key order.
	page, total, err := repo.ListBusinessAssetsPage(ctx, "tpage-a", ports.BusinessAssetQuery{Limit: 1, Offset: 1})
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	if total != 3 {
		t.Fatalf("total = %d, want 3 matches regardless of the page size", total)
	}
	if len(page) != 1 || page[0].Key != "billing" {
		t.Fatalf("offset 1 = %v, want billing in key order", page)
	}

	// Another tenant's rows never appear.
	if _, total, err = repo.ListBusinessAssetsPage(ctx, "tpage-b", ports.BusinessAssetQuery{Limit: 10}); err != nil || total != 1 {
		t.Fatalf("tenant-b total = %d err=%v, want only its own row", total, err)
	}
}

// The dashboard pages the inventory, and a caller that walks the pages must see every asset
// exactly once no matter which store answered. That holds only if both stores order the same way
// and clamp the same way, so this asserts the two against each other rather than against a
// hand-written expectation.
//
// Ordering is the part that silently diverges: the memory twin sorts Go strings by byte, while
// Postgres orders by the database collation, and an ICU-initialised cluster puts "_infra" before
// "Billing" where Go does the reverse. Mixed-case and punctuation-leading keys are what expose it.
func TestListBusinessAssetsPageMatchesMemoryTwin(t *testing.T) {
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
	t.Cleanup(func() { pool.Close() })

	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ('ttwin-a','A') ON CONFLICT (id) DO NOTHING`); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM fleet_business_services WHERE tenant_id = 'ttwin-a'`)
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id = 'ttwin-a'`)
	})

	repo := NewAssetRepository(pool)
	twin := memory.NewAssetStore()
	now := time.Now().UTC().Truncate(time.Second)
	// Upper case, lower case and a leading underscore: byte order and collation order disagree
	// on every one of these pairs.
	for _, key := range []string{"Billing", "_infra", "alpha", "api-gateway", "apigateway"} {
		ba, err := asset.NewBusinessAsset(shared.ID("twin-"+key), "ttwin-a", key, "Name "+key, "", asset.BusinessAssetApplication, asset.CriticalityLow, "platform-team", nil, "operator", now)
		if err != nil {
			t.Fatalf("new business asset %q: %v", key, err)
		}
		if err := repo.CreateBusinessAsset(ctx, ba); err != nil {
			t.Fatalf("create %q in postgres: %v", key, err)
		}
		if err := twin.CreateBusinessAsset(ctx, ba); err != nil {
			t.Fatalf("create %q in memory: %v", key, err)
		}
	}

	cases := []struct {
		name  string
		query ports.BusinessAssetQuery
	}{
		{"first page", ports.BusinessAssetQuery{Limit: 2}},
		{"second page", ports.BusinessAssetQuery{Limit: 2, Offset: 2}},
		{"last partial page", ports.BusinessAssetQuery{Limit: 2, Offset: 4}},
		// Past the end is a real request: a caller holding a stale page count asks for it.
		{"offset past the end", ports.BusinessAssetQuery{Limit: 2, Offset: 99}},
		// A non-positive limit asks for the count without the rows.
		{"count only", ports.BusinessAssetQuery{Limit: 0}},
		{"negative limit", ports.BusinessAssetQuery{Limit: -1}},
		// A negative offset is clamped rather than refused or passed to the database.
		{"negative offset", ports.BusinessAssetQuery{Limit: 2, Offset: -5}},
		{"filtered count only", ports.BusinessAssetQuery{Limit: 0, Query: "api"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotItems, gotTotal, err := repo.ListBusinessAssetsPage(ctx, "ttwin-a", tc.query)
			if err != nil {
				t.Fatalf("postgres: %v", err)
			}
			wantItems, wantTotal, err := twin.ListBusinessAssetsPage(ctx, "ttwin-a", tc.query)
			if err != nil {
				t.Fatalf("memory: %v", err)
			}
			if gotTotal != wantTotal {
				t.Fatalf("total: postgres %d, memory %d", gotTotal, wantTotal)
			}
			gotKeys, wantKeys := keysOf(gotItems), keysOf(wantItems)
			if !slices.Equal(gotKeys, wantKeys) {
				t.Fatalf("page: postgres %v, memory %v", gotKeys, wantKeys)
			}
			// A page the caller can display must not claim more rows than the filter matched.
			if len(gotItems) > gotTotal {
				t.Fatalf("page of %d rows reported a total of %d", len(gotItems), gotTotal)
			}
		})
	}

	// The count-only branch must still count, not return zero because it returned no rows.
	if _, total, err := repo.ListBusinessAssetsPage(ctx, "ttwin-a", ports.BusinessAssetQuery{Limit: 0}); err != nil || total != 5 {
		t.Fatalf("count-only total = %d err = %v, want 5", total, err)
	}
}

func keysOf(items []*asset.BusinessAsset) []string {
	out := make([]string, 0, len(items))
	for _, a := range items {
		out = append(out, a.Key)
	}
	return out
}
