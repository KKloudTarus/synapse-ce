package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	etTenant = shared.ID("tenant-et")
	etAsset  = shared.ID("asset-et")
)

var etBase = time.Unix(1_800_000_000, 0).UTC()

func etCtx(tenant shared.ID) context.Context {
	return shared.WithTenant(context.Background(), tenant)
}

func entry(tenant, asset, eventID string, occ time.Time, kind endpoint.TimelineEntryKind, entityID string) endpoint.TimelineEntry {
	return endpoint.TimelineEntry{
		OccurredAt: occ, TenantID: shared.ID(tenant), AssetID: shared.ID(asset),
		EntityKind: entityKindFor(kind), EntityID: shared.ID(entityID), Kind: kind,
		EventID: shared.ID(eventID), Summary: eventID,
	}
}

// entityKindFor keeps the test entries consistent with the entry kind.
func entityKindFor(k endpoint.TimelineEntryKind) endpoint.EntityKind {
	switch k {
	case endpoint.TimelineNetworkConnect:
		return endpoint.EntityNetwork
	case endpoint.TimelinePrivilegeChange:
		return endpoint.EntityIdentity
	default:
		return endpoint.EntityProcess
	}
}

func TestEndpointTimelineAppendQueryAndIdempotency(t *testing.T) {
	s := NewEndpointTimelineStore()
	ctx := etCtx(etTenant)
	// Append out of event-time order; query must return event-time order.
	in := []endpoint.TimelineEntry{
		entry(string(etTenant), string(etAsset), "c", etBase.Add(2*time.Second), endpoint.TimelineProcessExec, "pe1"),
		entry(string(etTenant), string(etAsset), "a", etBase, endpoint.TimelineProcessStart, "pe1"),
		entry(string(etTenant), string(etAsset), "b", etBase.Add(time.Second), endpoint.TimelineNetworkConnect, "nc1"),
	}
	if err := s.AppendTimeline(ctx, in); err != nil {
		t.Fatal(err)
	}
	// Re-append the same events (idempotent) plus a duplicate of "a".
	if err := s.AppendTimeline(ctx, in); err != nil {
		t.Fatal(err)
	}
	got, err := s.QueryTimeline(ctx, ports.EndpointTimelineQuery{AssetID: etAsset})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("idempotent append must yield 3 entries, got %d", len(got))
	}
	if string(got[0].EventID) != "a" || string(got[1].EventID) != "b" || string(got[2].EventID) != "c" {
		t.Fatalf("not event-time ordered: %v %v %v", got[0].EventID, got[1].EventID, got[2].EventID)
	}
}

func TestEndpointTimelineQueryFilters(t *testing.T) {
	s := NewEndpointTimelineStore()
	ctx := etCtx(etTenant)
	_ = s.AppendTimeline(ctx, []endpoint.TimelineEntry{
		entry(string(etTenant), string(etAsset), "a", etBase, endpoint.TimelineProcessStart, "pe1"),
		entry(string(etTenant), string(etAsset), "b", etBase.Add(time.Hour), endpoint.TimelineNetworkConnect, "nc1"),
		entry(string(etTenant), string(etAsset), "c", etBase.Add(2*time.Hour), endpoint.TimelineProcessExec, "pe1"),
	})
	// Time window.
	win, _ := s.QueryTimeline(ctx, ports.EndpointTimelineQuery{AssetID: etAsset, From: etBase.Add(30 * time.Minute), To: etBase.Add(90 * time.Minute)})
	if len(win) != 1 || win[0].EventID != "b" {
		t.Fatalf("time window filter wrong: %+v", win)
	}
	// Entity filter.
	ent, _ := s.QueryTimeline(ctx, ports.EndpointTimelineQuery{AssetID: etAsset, EntityID: "pe1"})
	if len(ent) != 2 {
		t.Fatalf("entity filter wrong: %+v", ent)
	}
	// Kind filter.
	kind, _ := s.QueryTimeline(ctx, ports.EndpointTimelineQuery{AssetID: etAsset, Kind: endpoint.TimelineNetworkConnect})
	if len(kind) != 1 || kind[0].EventID != "b" {
		t.Fatalf("kind filter wrong: %+v", kind)
	}
	// Limit.
	lim, _ := s.QueryTimeline(ctx, ports.EndpointTimelineQuery{AssetID: etAsset, Limit: 2})
	if len(lim) != 2 {
		t.Fatalf("limit wrong: %+v", lim)
	}
}

func TestEndpointTimelineTenantIsolationAndFailClosed(t *testing.T) {
	s := NewEndpointTimelineStore()
	other := shared.ID("tenant-other")
	// Tenant A writes; tenant B must not see it.
	if err := s.AppendTimeline(etCtx(etTenant), []endpoint.TimelineEntry{
		entry(string(etTenant), string(etAsset), "a", etBase, endpoint.TimelineProcessStart, "pe1"),
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.QueryTimeline(etCtx(other), ports.EndpointTimelineQuery{AssetID: etAsset})
	if len(got) != 0 {
		t.Fatalf("cross-tenant read must see nothing, got %d", len(got))
	}
	// An entry whose tenant differs from the context tenant is rejected.
	if err := s.AppendTimeline(etCtx(etTenant), []endpoint.TimelineEntry{
		entry(string(other), string(etAsset), "x", etBase, endpoint.TimelineProcessStart, "pe1"),
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("cross-tenant write must be rejected, got %v", err)
	}
	// Missing tenant in context is rejected on both paths.
	if err := s.AppendTimeline(context.Background(), nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("append without tenant must be rejected, got %v", err)
	}
	if _, err := s.QueryTimeline(context.Background(), ports.EndpointTimelineQuery{AssetID: etAsset}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("query without tenant must be rejected, got %v", err)
	}
	// Query requires an asset id.
	if _, err := s.QueryTimeline(etCtx(etTenant), ports.EndpointTimelineQuery{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("query without asset must be rejected, got %v", err)
	}
}
