package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestFleetDesiredRepositoryRejectsDuplicatePolicyIDWithinTenant(t *testing.T) {
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

	const tenant = "fd-policy-id"
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$1) ON CONFLICT (id) DO NOTHING`, tenant); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_ = WithTenant(bg, pool, tenant, func(tx pgx.Tx) error {
			if _, err := tx.Exec(bg, `DELETE FROM fleet_desired_state WHERE tenant_id=$1`, tenant); err != nil {
				return err
			}
			_, err := tx.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id=$1 AND id LIKE 'fd-policy-asset-%'`, tenant)
			return err
		})
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tenant)
	})

	now := time.Date(2026, 8, 19, 4, 0, 0, 0, time.UTC)
	assets := NewAssetRepository(pool)
	for _, id := range []shared.ID{"fd-policy-asset-a", "fd-policy-asset-b"} {
		a, err := asset.New(id, tenant, asset.KindHost, "key/"+id.String(), id.String(), nil, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := assets.UpsertAsset(ctx, a); err != nil {
			t.Fatal(err)
		}
	}

	repo := NewFleetDesiredRepository(pool)
	first := &fleetdesired.State{
		TenantID: tenant, AssetID: "fd-policy-asset-a", PolicyID: "policy-shared",
		Capabilities: []string{"process"}, UpdatedBy: "operator", Version: 1,
		Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
	second := &fleetdesired.State{
		TenantID: tenant, AssetID: "fd-policy-asset-b", PolicyID: "policy-shared",
		Capabilities: []string{"network"}, UpdatedBy: "operator", Version: 1,
		Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
	if err := repo.Put(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := repo.Put(ctx, second); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate PolicyID error=%v, want ErrConflict", err)
	}
	if _, err := repo.Get(ctx, tenant, "fd-policy-asset-b"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("conflicting policy persisted: %v", err)
	}
	got, err := repo.Get(ctx, tenant, "fd-policy-asset-a")
	if err != nil {
		t.Fatal(err)
	}
	if got.PolicyID != "policy-shared" || got.Capabilities[0] != "process" {
		t.Fatalf("existing policy changed after duplicate PolicyID conflict: %+v", got)
	}
}

func TestFleetDesiredRepositoryDeleteRecreateRejectsStaleLifecycleDelete(t *testing.T) {
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

	const (
		tenant  = "fd-policy-aba"
		assetID = "fd-policy-asset-aba"
	)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$1) ON CONFLICT (id) DO NOTHING`, tenant); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_ = WithTenant(bg, pool, tenant, func(tx pgx.Tx) error {
			if _, err := tx.Exec(bg, `DELETE FROM fleet_desired_state WHERE tenant_id=$1`, tenant); err != nil {
				return err
			}
			_, err := tx.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id=$1 AND id=$2`, tenant, assetID)
			return err
		})
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tenant)
	})

	now := time.Date(2026, 8, 19, 5, 0, 0, 0, time.UTC)
	assets := NewAssetRepository(pool)
	a, err := asset.New(assetID, tenant, asset.KindHost, "key/"+assetID, assetID, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := assets.UpsertAsset(ctx, a); err != nil {
		t.Fatal(err)
	}

	repo := NewFleetDesiredRepository(pool)
	old := &fleetdesired.State{
		TenantID: tenant, AssetID: assetID, PolicyID: "policy-old", Capabilities: []string{"process"},
		UpdatedBy: "operator", Version: 1, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
	if err := repo.Put(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := repo.Delete(ctx, tenant, assetID, "policy-old", 1); err != nil {
		t.Fatal(err)
	}
	fresh := &fleetdesired.State{
		TenantID: tenant, AssetID: assetID, PolicyID: "policy-new", Capabilities: []string{"network"},
		UpdatedBy: "operator", Version: 1, Audit: shared.Audit{CreatedAt: now.Add(time.Minute), UpdatedAt: now.Add(time.Minute)},
	}
	if err := repo.Put(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if err := repo.Delete(ctx, tenant, assetID, "policy-old", 1); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale lifecycle delete error=%v, want ErrConflict", err)
	}
	got, err := repo.Get(ctx, tenant, assetID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PolicyID != "policy-new" || got.Version != 1 || len(got.Capabilities) != 1 || got.Capabilities[0] != "network" {
		t.Fatalf("stale lifecycle delete changed recreated policy: %+v", got)
	}
}
