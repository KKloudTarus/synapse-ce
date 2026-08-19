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

func TestFleetDesiredRepository(t *testing.T) {
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

	for _, tenant := range []string{"fd-a", "fd-b"} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`, tenant, tenant); err != nil {
			t.Fatalf("seed tenant %s: %v", tenant, err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		for _, tenant := range []string{"fd-a", "fd-b"} {
			_ = WithTenant(bg, pool, tenant, func(tx pgx.Tx) error {
				if _, err := tx.Exec(bg, `DELETE FROM fleet_desired_state WHERE tenant_id=$1`, tenant); err != nil {
					return err
				}
				_, err := tx.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id=$1 AND id LIKE 'fd-asset-%'`, tenant)
				return err
			})
		}
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id IN ('fd-a','fd-b')`)
	})

	var forced bool
	if err := pool.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE relname='fleet_desired_state'`).Scan(&forced); err != nil {
		t.Fatalf("read desired-state RLS flag: %v", err)
	}
	if !forced {
		t.Fatal("FORCE RLS not set on fleet_desired_state")
	}

	now := time.Now().UTC().Truncate(time.Second)
	assetRepo := NewAssetRepository(pool)
	createAsset := func(tenant, id string, kind asset.Kind) {
		t.Helper()
		a, err := asset.New(shared.ID(id), shared.ID(tenant), kind, "key/"+id, id, nil, now)
		if err != nil {
			t.Fatalf("new asset %s: %v", id, err)
		}
		if err := assetRepo.UpsertAsset(ctx, a); err != nil {
			t.Fatalf("create asset %s: %v", id, err)
		}
	}
	createAsset("fd-a", "fd-asset-a", asset.KindHost)
	createAsset("fd-a", "fd-asset-c", asset.KindHost)
	createAsset("fd-b", "fd-asset-b", asset.KindCluster)

	gotAsset, err := assetRepo.GetAssetByID(ctx, "fd-a", "fd-asset-a")
	if err != nil || gotAsset.ID != "fd-asset-a" || gotAsset.Kind != asset.KindHost {
		t.Fatalf("asset id lookup mismatch: asset=%+v err=%v", gotAsset, err)
	}
	if _, err := assetRepo.GetAssetByID(ctx, "fd-b", "fd-asset-a"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant asset id lookup=%v, want ErrNotFound", err)
	}

	repo := NewFleetDesiredRepository(pool)
	state := &fleetdesired.State{
		TenantID: "fd-a", AssetID: "fd-asset-a", PolicyID: "policy-a", Capabilities: []string{"inventory.host", "telemetry.process"},
		UpdatedBy: "operator-a", Version: 1, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
	if err := repo.Put(ctx, state); err != nil {
		t.Fatalf("put desired state: %v", err)
	}

	got, err := repo.Get(ctx, "fd-a", "fd-asset-a")
	if err != nil {
		t.Fatalf("get desired state: %v", err)
	}
	if got.PolicyID != "policy-a" || got.Version != 1 || len(got.Capabilities) != 2 || got.Capabilities[0] != "inventory.host" || got.Capabilities[1] != "telemetry.process" {
		t.Fatalf("desired state did not round-trip: %+v", got)
	}
	if got.UpdatedBy != "operator-a" || !got.Audit.CreatedAt.Equal(now) {
		t.Fatalf("desired attribution/audit did not round-trip: %+v", got)
	}

	updatedAt := now.Add(time.Minute)
	update := &fleetdesired.State{
		TenantID: "fd-a", AssetID: "fd-asset-a", PolicyID: "policy-a", Capabilities: []string{"telemetry.network"},
		UpdatedBy: "operator-b", Version: 2,
		// The repository owns creation history and preserves the original value on conflict.
		Audit: shared.Audit{CreatedAt: now.Add(-time.Hour), UpdatedAt: updatedAt},
	}
	if err := repo.Put(ctx, update); err != nil {
		t.Fatalf("update desired state: %v", err)
	}
	got, err = repo.Get(ctx, "fd-a", "fd-asset-a")
	if err != nil {
		t.Fatalf("get updated desired state: %v", err)
	}
	if got.PolicyID != "policy-a" || got.Version != 2 || !got.Audit.CreatedAt.Equal(now) || !got.Audit.UpdatedAt.Equal(updatedAt) || got.UpdatedBy != "operator-b" || len(got.Capabilities) != 1 || got.Capabilities[0] != "telemetry.network" {
		t.Fatalf("upsert history/mutable state mismatch: %+v", got)
	}

	// The caller may not forge an earlier CreatedAt to make an UpdatedAt that predates the persisted
	// lifecycle appear valid. PostgreSQL must expose the same ErrValidation contract as the memory store.
	backdated := &fleetdesired.State{
		TenantID: "fd-a", AssetID: "fd-asset-a", PolicyID: "policy-a", Capabilities: []string{"telemetry.file"},
		UpdatedBy: "operator-c", Version: 3,
		Audit: shared.Audit{CreatedAt: now.Add(-2 * time.Hour), UpdatedAt: now.Add(-time.Minute)},
	}
	if err := repo.Put(ctx, backdated); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("backdated desired update=%v, want ErrValidation", err)
	}
	got, err = repo.Get(ctx, "fd-a", "fd-asset-a")
	if err != nil || got.Version != 2 || got.Capabilities[0] != "telemetry.network" || !got.Audit.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("backdated update changed stored policy: got=%+v err=%v", got, err)
	}

	// Replaying another version 2 after version 2 is already current is a stale concurrent writer.
	stale := &fleetdesired.State{
		TenantID: "fd-a", AssetID: "fd-asset-a", PolicyID: "policy-a", Capabilities: []string{"telemetry.file"},
		UpdatedBy: "stale-operator", Version: 2,
		Audit: shared.Audit{CreatedAt: now, UpdatedAt: updatedAt.Add(time.Minute)},
	}
	if err := repo.Put(ctx, stale); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale desired update=%v, want ErrConflict", err)
	}
	if err := repo.Delete(ctx, "fd-a", "fd-asset-a", "policy-a", 1); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale desired delete=%v, want ErrConflict", err)
	}
	got, err = repo.Get(ctx, "fd-a", "fd-asset-a")
	if err != nil || got.PolicyID != "policy-a" || got.Version != 2 || got.Capabilities[0] != "telemetry.network" {
		t.Fatalf("stale operation changed version 2 state: got=%+v err=%v", got, err)
	}

	if _, err := repo.Get(ctx, "fd-b", "fd-asset-a"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant desired lookup=%v, want ErrNotFound", err)
	}
	rows, err := repo.List(ctx, "fd-a")
	if err != nil || len(rows) != 1 || rows[0].AssetID != "fd-asset-a" || rows[0].PolicyID != "policy-a" || rows[0].Version != 2 {
		t.Fatalf("tenant desired list mismatch: rows=%+v err=%v", rows, err)
	}

	// Prove the RLS policy itself with a real NOSUPERUSER/NOBYPASSRLS role when CI connects as postgres.
	activateRLSRole := fleetDesiredRLSRole(t, ctx, pool)
	var visible int
	if err := WithTenant(ctx, pool, "fd-b", func(tx pgx.Tx) error {
		if err := activateRLSRole(ctx, tx); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM fleet_desired_state WHERE tenant_id='fd-a'`).Scan(&visible)
	}); err != nil {
		t.Fatalf("direct cross-tenant RLS read: %v", err)
	}
	if visible != 0 {
		t.Fatalf("RLS leaked %d fd-a desired rows to fd-b", visible)
	}
	var crossTenantUpdated int64
	if err := WithTenant(ctx, pool, "fd-b", func(tx pgx.Tx) error {
		if err := activateRLSRole(ctx, tx); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE fleet_desired_state SET updated_by='intruder' WHERE tenant_id='fd-a' AND asset_id='fd-asset-a'`)
		if err == nil {
			crossTenantUpdated = tag.RowsAffected()
		}
		return err
	}); err != nil {
		t.Fatalf("direct cross-tenant RLS update: %v", err)
	}
	if crossTenantUpdated != 0 {
		t.Fatalf("RLS permitted %d cross-tenant updates", crossTenantUpdated)
	}

	// The FK independently rejects a desired row whose canonical technical asset does not exist.
	missingAsset := &fleetdesired.State{
		TenantID: "fd-a", AssetID: "fd-asset-missing", PolicyID: "policy-missing", Capabilities: []string{"process"},
		UpdatedBy: "operator", Version: 1, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
	if err := repo.Put(ctx, missingAsset); err == nil {
		t.Fatal("desired state for a missing canonical asset unexpectedly persisted")
	}

	// Bypass the repository validator and prove the SQL CHECK rejects a non-canonical capability array.
	var invalidInserted int64
	if err := WithTenant(ctx, pool, "fd-a", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			INSERT INTO fleet_desired_state
			  (tenant_id,asset_id,policy_id,capabilities,updated_by,version,created_at,updated_at)
			VALUES ('fd-a','fd-asset-c','policy-direct-invalid',ARRAY['z','a'],'operator',1,now(),now())`)
		if err == nil {
			invalidInserted = tag.RowsAffected()
		}
		return err
	}); err == nil {
		t.Fatal("unsorted capability array unexpectedly bypassed database canonicality CHECK")
	}
	if invalidInserted != 0 {
		t.Fatalf("invalid direct insert affected %d rows", invalidInserted)
	}

	if err := repo.Delete(ctx, "fd-a", "fd-asset-a", "policy-a", 2); err != nil {
		t.Fatalf("delete desired state: %v", err)
	}
	if err := repo.Delete(ctx, "fd-a", "fd-asset-a", "policy-a", 2); err != nil {
		t.Fatalf("idempotent delete desired state: %v", err)
	}
	if _, err := repo.Get(ctx, "fd-a", "fd-asset-a"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("deleted desired state lookup=%v, want ErrNotFound", err)
	}
}
