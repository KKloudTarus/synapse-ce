package postgres

import (
	"context"
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
	if err := Migrate(ctx, dsn); err != nil {
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

	// Edge roundtrip + idempotency (ON CONFLICT DO NOTHING).
	e, _ := asset.NewEdge("ta", "as1", "as2", asset.EdgeRuns, "obs1")
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
	if len(edges) != 1 || edges[0].Kind != asset.EdgeRuns {
		t.Fatalf("expected one runs edge, got %+v", edges)
	}

	// Business service roundtrip + idempotency.
	svc, _ := asset.NewBusinessService("s1", "ta", "payments", "team-a", now)
	if err := repo.UpsertBusinessService(ctx, svc); err != nil {
		t.Fatalf("upsert svc: %v", err)
	}
	svc2, _ := asset.NewBusinessService("s1", "ta", "payments", "team-b", now)
	if err := repo.UpsertBusinessService(ctx, svc2); err != nil {
		t.Fatalf("re-upsert svc: %v", err)
	}
	svcs, err := repo.ListBusinessServices(ctx, "ta")
	if err != nil {
		t.Fatalf("list svcs: %v", err)
	}
	if len(svcs) != 1 || svcs[0].Owner != "team-b" {
		t.Fatalf("expected one service with updated owner, got %+v", svcs)
	}

	// Empty tenant is rejected by the domain before it ever reaches the DB.
	if _, err := asset.New("z", "", asset.KindHost, "h", "h", nil, now); err == nil {
		t.Fatalf("empty tenant asset should be rejected by domain")
	}
	_ = shared.ID("")
}
