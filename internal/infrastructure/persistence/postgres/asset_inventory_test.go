package postgres

import (
	"context"
	"errors"
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"net/url"
	"testing"
	"time"
)

func TestAssetInventoryRLSIsolation(t *testing.T) {
	dsn := testDSN(t)
	ctx := context.Background()
	if err := Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	admin, err := Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	if _, err := admin.Exec(ctx, `DELETE FROM assessments; DELETE FROM appsec_asset_ownership_assignments; DELETE FROM appsec_asset_relationships; DELETE FROM appsec_business_service_assets; DELETE FROM appsec_asset_versions; DELETE FROM appsec_business_services; DELETE FROM appsec_assets`); err != nil {
		t.Fatal(err)
	}
	role := fmt.Sprintf("asset_runtime_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, `CREATE ROLE `+role+` LOGIN PASSWORD 'asset-runtime-test'`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `GRANT USAGE ON SCHEMA public TO `+role+`; GRANT SELECT, INSERT, UPDATE, DELETE ON appsec_assets, appsec_asset_versions, appsec_business_services, appsec_business_service_assets, appsec_asset_relationships, appsec_asset_ownership_assignments TO `+role); err != nil {
		t.Fatal(err)
	}
	runtimeURL, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	runtimeURL.User = url.UserPassword(role, "asset-runtime-test")
	runtime, err := Connect(ctx, runtimeURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.Close(); _, _ = admin.Exec(ctx, `DROP ROLE `+role) })
	repo := NewAssetInventoryRepository(runtime)
	now := time.Now().UTC()
	ctxA := shared.WithTenant(ctx, "asset-tenant-a")
	ctxB := shared.WithTenant(ctx, "asset-tenant-b")
	for _, tenant := range []shared.ID{"asset-tenant-a", "asset-tenant-b"} {
		if _, err := admin.Exec(ctx, `INSERT INTO tenants (id,name) VALUES ($1,$1) ON CONFLICT (id) DO NOTHING`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	a := mustPostgresAsset(t, "asset-a", "asset-tenant-a", now)
	if err := repo.CreateAsset(ctxA, a); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetAsset(ctxB, a.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get error=%v", err)
	}
	if list, err := repo.ListAssets(ctxB); err != nil || len(list) != 0 {
		t.Fatalf("tenant B list=%+v err=%v", list, err)
	}
	service := asset.BusinessService{ID: "service-a", TenantID: "asset-tenant-a", Name: "Payments", Criticality: asset.CriticalityHigh, Lifecycle: asset.LifecycleActive, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now}}
	if err := repo.CreateBusinessService(ctxA, service); err != nil {
		t.Fatal(err)
	}
	if err := repo.LinkBusinessServiceAsset(ctxA, asset.BusinessServiceAssetLink{BusinessServiceID: service.ID, AssetID: a.ID, Role: asset.AssetLinkOwns, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := repo.LinkBusinessServiceAsset(ctxB, asset.BusinessServiceAssetLink{BusinessServiceID: service.ID, AssetID: a.ID, Role: asset.AssetLinkUses, CreatedAt: now}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant link error=%v", err)
	}
}

func mustPostgresAsset(t *testing.T, id, tenant string, now time.Time) asset.Asset {
	t.Helper()
	a, err := asset.New(shared.ID(id), shared.ID(tenant), "Payments API", asset.CategoryAPI, asset.Identity{Kind: "url", Value: "https://payments.example.test"}, now)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
