package retrohunt

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/endpoint"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

const (
	tenant = shared.ID("tenant-rh")
	asset  = shared.ID("asset-rh")
)

var base = time.Unix(1_800_000_000, 0).UTC()

func newSvc(t *testing.T) (*Service, context.Context, *memory.EndpointTimelineStore) {
	t.Helper()
	store := memory.NewEndpointTimelineStore()
	svc, err := NewService(store)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc, shared.WithTenant(context.Background(), tenant), store
}

func entry(eventID string, occ time.Time, entity string) endpoint.TimelineEntry {
	return endpoint.TimelineEntry{
		OccurredAt: occ, TenantID: tenant, AssetID: asset, EntityKind: endpoint.EntityProcess,
		EntityID: shared.ID(entity), Kind: endpoint.TimelineProcessExec, EventID: shared.ID(eventID), Summary: eventID,
	}
}

func seed(t *testing.T, ctx context.Context, store *memory.EndpointTimelineStore) {
	t.Helper()
	if err := store.AppendTimeline(ctx, []endpoint.TimelineEntry{
		entry("e-before", base.Add(-2*time.Minute), "pe-1"),
		entry("e-just-before", base.Add(-10*time.Second), "pe-1"),
		entry("e-at", base, "pe-2"),
		entry("e-just-after", base.Add(10*time.Second), "pe-1"),
		entry("e-far-after", base.Add(2*time.Hour), "pe-1"),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestHuntReturnsSurroundingWindow(t *testing.T) {
	svc, ctx, store := newSvc(t)
	seed(t, ctx, store)
	res, err := svc.Hunt(ctx, Request{AssetID: asset, Around: base, Before: time.Minute, After: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	// e-just-before, e-at, e-just-after are within +/-1min; e-before(-2m) and e-far-after(+2h) are not.
	if len(res.Entries) != 3 {
		t.Fatalf("expected 3 entries in window, got %d: %+v", len(res.Entries), res.Entries)
	}
	if string(res.Entries[0].EventID) != "e-just-before" || string(res.Entries[2].EventID) != "e-just-after" {
		t.Fatalf("window not event-time ordered: %+v", res.Entries)
	}
	if !res.From.Equal(base.Add(-time.Minute)) || !res.To.Equal(base.Add(time.Minute)) {
		t.Fatalf("window bounds wrong: [%s,%s]", res.From, res.To)
	}
}

func TestHuntEntityFilter(t *testing.T) {
	svc, ctx, store := newSvc(t)
	seed(t, ctx, store)
	res, err := svc.Hunt(ctx, Request{AssetID: asset, Around: base, Before: time.Minute, After: time.Minute, EntityID: "pe-2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 1 || res.Entries[0].EntityID != "pe-2" {
		t.Fatalf("entity filter wrong: %+v", res.Entries)
	}
}

func TestHuntTruncation(t *testing.T) {
	svc, ctx, store := newSvc(t)
	seed(t, ctx, store)
	res, err := svc.Hunt(ctx, Request{AssetID: asset, Around: base, Before: time.Hour, After: 3 * time.Hour, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != 2 || !res.Truncated {
		t.Fatalf("expected truncated 2-entry result, got %d truncated=%v", len(res.Entries), res.Truncated)
	}
}

func TestHuntFailsClosed(t *testing.T) {
	svc, ctx, _ := newSvc(t)
	bad := []Request{
		{Around: base, Before: time.Minute},                            // no asset
		{AssetID: asset, Before: time.Minute},                          // no trigger time
		{AssetID: asset, Around: base, Before: -1, After: time.Minute}, // negative look-back
		{AssetID: asset, Around: base},                                 // zero-width window
	}
	for i, req := range bad {
		if _, err := svc.Hunt(ctx, req); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("case %d must fail closed, got %v", i, err)
		}
	}
	if _, err := NewService(nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("nil store must be rejected")
	}
}

func TestHuntDefaultLimitReportsTruncation(t *testing.T) {
	svc, ctx, store := newSvc(t)
	// Seed more than the usecase default bound within the window, all with distinct event ids/times.
	var entries []endpoint.TimelineEntry
	for i := 0; i < defaultHuntLimit+1; i++ {
		entries = append(entries, entry("e-"+strconv.Itoa(i), base.Add(time.Duration(i)*time.Millisecond), "pe-1"))
	}
	if err := store.AppendTimeline(ctx, entries); err != nil {
		t.Fatal(err)
	}
	// With no explicit Limit, the window is capped at the usecase default AND reported truncated (honest).
	res, err := svc.Hunt(ctx, Request{AssetID: asset, Around: base, Before: time.Second, After: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) != defaultHuntLimit || !res.Truncated {
		t.Fatalf("default-limit cap must be reported truncated: len=%d truncated=%v", len(res.Entries), res.Truncated)
	}
}

func TestHuntDefaultLimitNotSpuriouslyTruncated(t *testing.T) {
	svc, ctx, store := newSvc(t)
	seed(t, ctx, store)
	res, err := svc.Hunt(ctx, Request{AssetID: asset, Around: base, Before: time.Minute, After: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if res.Truncated {
		t.Fatal("a small window must not be reported truncated under the default limit")
	}
}
