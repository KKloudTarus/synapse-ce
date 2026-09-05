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

// TestEndpointProcessReplaceRetiresExitedProcesses is the Postgres regression for the unbounded-growth
// bug: a complete report replaces the asset's running set (upsert reported + retire absent) in one
// transaction, so a process reported once and then omitted is marked not-running, and another asset's
// rows are untouched.
func TestEndpointProcessReplaceRetiresExitedProcesses(t *testing.T) {
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
	tenant := shared.ID("epr-" + id)
	assetA := shared.ID("epr-a-" + id)
	assetB := shared.ID("epr-b-" + id)
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name) VALUES($1,$1)`, tenant.String()); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	for _, a := range []shared.ID{assetA, assetB} {
		if _, err := pool.Exec(ctx, `INSERT INTO fleet_assets(id,tenant_id,kind,"key",name) VALUES($1,$2,'host',$1,$1)`, a.String(), tenant.String()); err != nil {
			t.Fatalf("seed asset: %v", err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM endpoint_processes WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id=$1`, tenant.String())
		_, _ = pool.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tenant.String())
	})
	repo := NewEndpointProcessRepository(pool)
	tctx := shared.WithTenant(ctx, tenant)
	now := time.Unix(1_800_000_100, 0).UTC()
	snapA := func(entity string) ports.ProcessSnapshot {
		return ports.ProcessSnapshot{TenantID: tenant, AssetID: assetA, EntityID: shared.ID(entity), PID: 7, Comm: "x", Path: "/x", Running: true, LastSeenAt: now}
	}
	// Seed asset B so we can prove a replace on A leaves B alone.
	if err := repo.ReplaceRunningProcesses(tctx, assetB, []ports.ProcessSnapshot{{TenantID: tenant, AssetID: assetB, EntityID: "b1", PID: 1, Comm: "y", Path: "/y", Running: true, LastSeenAt: now}}); err != nil {
		t.Fatalf("seed B: %v", err)
	}
	// Sweep 1 on A: {e1,e2,e3}.
	if err := repo.ReplaceRunningProcesses(tctx, assetA, []ports.ProcessSnapshot{snapA("e1"), snapA("e2"), snapA("e3")}); err != nil {
		t.Fatalf("sweep1: %v", err)
	}
	if got, _ := repo.ListRunningByAsset(tctx, assetA); len(got) != 3 {
		t.Fatalf("A sweep1 running = %d, want 3", len(got))
	}
	// Sweep 2 on A: e2 exited, e4 spawned.
	if err := repo.ReplaceRunningProcesses(tctx, assetA, []ports.ProcessSnapshot{snapA("e1"), snapA("e3"), snapA("e4")}); err != nil {
		t.Fatalf("sweep2: %v", err)
	}
	got, _ := repo.ListRunningByAsset(tctx, assetA)
	if len(got) != 3 {
		t.Fatalf("A sweep2 running = %d, want 3 (e2 retired): %+v", len(got), got)
	}
	for _, p := range got {
		if p.EntityID == "e2" {
			t.Fatalf("e2 exited but still running: %+v", got)
		}
	}
	if b, _ := repo.ListRunningByAsset(tctx, assetB); len(b) != 1 || b[0].EntityID != "b1" {
		t.Fatalf("asset B running changed by an asset A replace: %+v", b)
	}
}
