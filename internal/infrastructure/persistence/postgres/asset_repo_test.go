package postgres

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
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
