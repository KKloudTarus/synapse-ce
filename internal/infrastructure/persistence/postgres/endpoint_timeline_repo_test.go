package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestEndpointTimelineRepository(t *testing.T) {
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
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	id := randHex(t)
	tenant := shared.ID("etl-" + id)
	other := shared.ID("etl-other-" + id)
	assetT := shared.ID("etl-asset-" + id)
	assetO := shared.ID("etl-asset-other-" + id)
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
		// endpoint_timeline is append-only (trigger); disable triggers on this one connection to clean up.
		conn, err := pool.Acquire(bg)
		if err != nil {
			return
		}
		defer conn.Release()
		if _, err := conn.Exec(bg, `SET session_replication_role = replica`); err != nil {
			return
		}
		defer conn.Exec(bg, `SET session_replication_role = origin`)
		for _, tn := range []shared.ID{tenant, other} {
			_, _ = conn.Exec(bg, `DELETE FROM endpoint_timeline WHERE tenant_id=$1`, tn.String())
			_, _ = conn.Exec(bg, `DELETE FROM fleet_assets WHERE tenant_id=$1`, tn.String())
			_, _ = conn.Exec(bg, `DELETE FROM tenants WHERE id=$1`, tn.String())
		}
	})

	repo := NewEndpointTimelineRepository(pool)
	tctx := shared.WithTenant(ctx, tenant)
	base := time.Unix(1_800_000_000, 0).UTC()

	mk := func(eventID string, occ time.Time, kind endpoint.TimelineEntryKind, entity string) endpoint.TimelineEntry {
		ek := endpoint.EntityProcess
		if kind == endpoint.TimelineNetworkConnect {
			ek = endpoint.EntityNetwork
		}
		return endpoint.TimelineEntry{
			OccurredAt: occ, TenantID: tenant, AssetID: assetT,
			EntityKind: ek, EntityID: shared.ID(entity), Kind: kind, EventID: shared.ID(eventID), Summary: eventID,
		}
	}
	in := []endpoint.TimelineEntry{
		mk("c", base.Add(2*time.Second), endpoint.TimelineProcessExec, "pe1"),
		mk("a", base, endpoint.TimelineProcessStart, "pe1"),
		mk("b", base.Add(time.Second), endpoint.TimelineNetworkConnect, "nc1"),
	}
	if err := repo.AppendTimeline(tctx, in); err != nil {
		t.Fatalf("append: %v", err)
	}
	// Idempotent re-append.
	if err := repo.AppendTimeline(tctx, in); err != nil {
		t.Fatalf("re-append: %v", err)
	}
	got, err := repo.QueryTimeline(tctx, ports.EndpointTimelineQuery{AssetID: assetT})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 3 || got[0].EventID != "a" || got[1].EventID != "b" || got[2].EventID != "c" {
		t.Fatalf("append/query not event-time ordered + idempotent: %+v", got)
	}
	if got[0].EntityID != "pe1" || got[0].Kind != endpoint.TimelineProcessStart || got[0].Summary != "a" {
		t.Fatalf("row round-trip wrong: %+v", got[0])
	}

	// Filters.
	if win, _ := repo.QueryTimeline(tctx, ports.EndpointTimelineQuery{AssetID: assetT, From: base.Add(500 * time.Millisecond), To: base.Add(1500 * time.Millisecond)}); len(win) != 1 || win[0].EventID != "b" {
		t.Fatalf("time window filter wrong: %+v", win)
	}
	if k, _ := repo.QueryTimeline(tctx, ports.EndpointTimelineQuery{AssetID: assetT, Kind: endpoint.TimelineNetworkConnect}); len(k) != 1 || k[0].EventID != "b" {
		t.Fatalf("kind filter wrong: %+v", k)
	}
	if e, _ := repo.QueryTimeline(tctx, ports.EndpointTimelineQuery{AssetID: assetT, EntityID: "pe1"}); len(e) != 2 {
		t.Fatalf("entity filter wrong: %+v", e)
	}
	if l, _ := repo.QueryTimeline(tctx, ports.EndpointTimelineQuery{AssetID: assetT, Limit: 2}); len(l) != 2 {
		t.Fatalf("limit wrong: %+v", l)
	}

	// Cross-tenant isolation: the other tenant's context sees nothing for this asset (RLS + predicate).
	octx := shared.WithTenant(ctx, other)
	if o, err := repo.QueryTimeline(octx, ports.EndpointTimelineQuery{AssetID: assetT}); err != nil || len(o) != 0 {
		t.Fatalf("cross-tenant read must see nothing, got %d err=%v", len(o), err)
	}
	// A cross-tenant entry is rejected before any write.
	if err := repo.AppendTimeline(tctx, []endpoint.TimelineEntry{{
		OccurredAt: base, TenantID: other, AssetID: assetT, EntityKind: endpoint.EntityProcess,
		EntityID: "pe1", Kind: endpoint.TimelineProcessStart, EventID: "x", Summary: "x",
	}}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("cross-tenant write must be rejected, got %v", err)
	}

	// The timeline is append-only (chain-of-custody): a direct UPDATE or DELETE is refused by the trigger.
	if _, err := pool.Exec(ctx, `UPDATE endpoint_timeline SET summary='tampered' WHERE tenant_id=$1`, tenant.String()); err == nil {
		t.Fatal("UPDATE on the append-only timeline must be rejected")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM endpoint_timeline WHERE tenant_id=$1`, tenant.String()); err == nil {
		t.Fatal("DELETE on the append-only timeline must be rejected")
	}
}
