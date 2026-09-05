package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestMigration0130HostAssetContext asserts the column and its partial unique index exist, then
// drives the repository round trip the host vulnerability use case relies on: a context created
// for a host asset is found by GetByHostAssetID, hidden from GetByIDInTenant and List, unique per
// (tenant, asset), and removed with its asset.
func TestMigration0130HostAssetContext(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := MigrateLocked(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	pool, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	var nullable string
	if err := pool.QueryRow(ctx,
		`SELECT is_nullable FROM information_schema.columns
		 WHERE table_schema='public' AND table_name='engagements' AND column_name='host_asset_id'`).Scan(&nullable); err != nil {
		t.Fatalf("host_asset_id column missing: %v", err)
	}
	if nullable != "YES" {
		t.Fatalf("host_asset_id must stay nullable, got %s", nullable)
	}
	var indexDef string
	if err := pool.QueryRow(ctx, `SELECT indexdef FROM pg_indexes WHERE tablename='engagements' AND indexname='idx_engagements_host_asset'`).Scan(&indexDef); err != nil {
		t.Fatalf("idx_engagements_host_asset missing: %v", err)
	}
	if !containsAll(indexDef, "UNIQUE", "tenant_id", "host_asset_id", "IS NOT NULL") {
		t.Fatalf("index is not a partial unique index on (tenant_id, host_asset_id): %s", indexDef)
	}

	tenant := shared.ID("t-0130-" + randHex(t))
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $1) ON CONFLICT DO NOTHING`, tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM engagements WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(ctx, `DELETE FROM fleet_assets WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenant.String())
	})

	now := time.Now().UTC().Truncate(time.Microsecond)
	assets := NewAssetRepository(pool)
	host, err := asset.New(shared.ID("host-"+randHex(t)), tenant, asset.KindHost, "machine-id/0130", "web01", map[string]string{"os": "linux"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := assets.UpsertAsset(ctx, host); err != nil {
		t.Fatalf("upsert asset: %v", err)
	}
	got, err := assets.GetAssetByID(ctx, tenant, host.ID)
	if err != nil || got.Key != host.Key {
		t.Fatalf("GetAssetByID = %+v, %v", got, err)
	}
	if _, err := assets.GetAssetByID(ctx, "other-tenant", host.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant GetAssetByID = %v, want ErrNotFound", err)
	}

	repo := NewEngagementRepository(pool)
	ctxEng, err := engagement.New(shared.ID("hostctx-"+randHex(t)), tenant, "web01 host vulnerabilities", "", now)
	if err != nil {
		t.Fatal(err)
	}
	ctxEng.HostAssetID = host.ID
	if err := ctxEng.SetScope([]engagement.Target{{Kind: engagement.TargetRepo, Value: "host://machine-id/0130"}}, nil, now); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, ctxEng); err != nil {
		t.Fatalf("create host context: %v", err)
	}

	found, err := repo.GetByHostAssetID(ctx, tenant, host.ID)
	if err != nil {
		t.Fatalf("GetByHostAssetID: %v", err)
	}
	if found.ID != ctxEng.ID || found.HostAssetID != host.ID || len(found.Scope.InScope) != 1 {
		t.Fatalf("host context round trip = %+v", found)
	}
	if _, err := repo.GetByIDInTenant(ctx, tenant, ctxEng.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("host context reachable through GetByIDInTenant: %v", err)
	}
	list, err := repo.List(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range list {
		if e.ID == ctxEng.ID {
			t.Fatalf("host context listed as an operator engagement")
		}
	}

	dup, _ := engagement.New(shared.ID("hostctx-dup-"+randHex(t)), tenant, "dup", "", now)
	dup.HostAssetID = host.ID
	if err := repo.Create(ctx, dup); err == nil {
		t.Fatalf("second context for the same host asset was accepted")
	}

	if _, err := pool.Exec(ctx, `DELETE FROM fleet_assets WHERE id=$1`, host.ID.String()); err != nil {
		t.Fatalf("delete asset: %v", err)
	}
	if _, err := repo.GetByHostAssetID(ctx, tenant, host.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("context survived its asset: %v", err)
	}
}
