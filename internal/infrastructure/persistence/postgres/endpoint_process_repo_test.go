package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestEndpointProcessRepository(t *testing.T) {
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

	id := randHex(t)
	tenant := shared.ID("ep-" + id)
	other := shared.ID("ep-other-" + id)
	assetT := shared.ID("ep-asset-" + id)
	assetO := shared.ID("ep-asset-other-" + id)
	for _, tn := range []shared.ID{tenant, other} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tn.String()); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
	}
	seedAsset := func(a, tn shared.ID) {
		if _, err := pool.Exec(ctx, `INSERT INTO fleet_assets(id,tenant_id,kind,"key",name) VALUES($1,$2,'host',$1,$1)`, a.String(), tn.String()); err != nil {
			t.Fatalf("seed asset: %v", err)
		}
	}
	seedAsset(assetT, tenant)
	seedAsset(assetO, other)
	t.Cleanup(func() {
		bg := context.Background()
		for _, tn := range []shared.ID{tenant, other} {
			_, _ = pool.Exec(bg, `DELETE FROM endpoint_processes WHERE tenant_id=$1`, tn.String())
			_, _ = pool.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id=$1`, tn.String())
			_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tn.String())
		}
	})

	repo := NewEndpointProcessRepository(pool)
	tctx := shared.WithTenant(ctx, tenant)
	octx := shared.WithTenant(ctx, other)
	now := time.Unix(1_800_000_000, 0).UTC()
	snap := func(entity string, running bool) ports.ProcessSnapshot {
		return ports.ProcessSnapshot{TenantID: tenant, AssetID: assetT, EntityID: shared.ID(entity), PID: 42, Comm: "curl", Path: "/usr/bin/curl", Running: running, LastSeenAt: now}
	}

	if err := repo.SaveProcesses(tctx, []ports.ProcessSnapshot{snap("e1", true), snap("e2", false), snap("e3", true)}); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := repo.ListRunningByAsset(tctx, assetT)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 || got[0].EntityID != "e1" || got[1].EntityID != "e3" {
		t.Fatalf("running filter/order wrong: %+v", got)
	}
	if got[0].Comm != "curl" || got[0].Path != "/usr/bin/curl" || got[0].PID != 42 {
		t.Fatalf("round-trip fields wrong: %+v", got[0])
	}
	// Upsert e1 -> exited, drops from running.
	if err := repo.SaveProcesses(tctx, []ports.ProcessSnapshot{snap("e1", false)}); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.ListRunningByAsset(tctx, assetT); len(got) != 1 || got[0].EntityID != "e3" {
		t.Fatalf("upsert to exited must drop from running, got %+v", got)
	}
	// Tenant isolation.
	if got, _ := repo.ListRunningByAsset(octx, assetO); len(got) != 0 {
		t.Fatalf("other tenant must see nothing, got %d", len(got))
	}
	// Cross-tenant snapshot rejected before touching the DB.
	if err := repo.SaveProcesses(tctx, []ports.ProcessSnapshot{{TenantID: other, AssetID: assetT, EntityID: "x", Running: true, LastSeenAt: now}}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("cross-tenant snapshot must be rejected, got %v", err)
	}
}
