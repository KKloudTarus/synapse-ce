package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	ieTenant = shared.ID("tenant-ie")
	ieAsset  = shared.ID("asset-ie")
	ieInc    = shared.ID("inc-ie")
)

var ieBase = time.Unix(1_800_000_000, 0).UTC()

func ieCtx(tenant shared.ID) context.Context { return shared.WithTenant(context.Background(), tenant) }

func createdEvent(inc, asset shared.ID) incident.IncidentEvent {
	return incident.IncidentEvent{IncidentID: inc, Kind: incident.EventCreated, At: ieBase, Actor: "c", AssetID: asset, Severity: shared.SeverityHigh, DetectionID: "d1"}
}

func TestIncidentEventStoreAppendOptimisticAndLoad(t *testing.T) {
	s := NewIncidentEventStore()
	ctx := ieCtx(ieTenant)
	if err := s.AppendEvents(ctx, ieInc, 0, []incident.IncidentEvent{createdEvent(ieInc, ieAsset)}); err != nil {
		t.Fatal(err)
	}
	// Append at wrong expected revision -> conflict.
	if err := s.AppendEvents(ctx, ieInc, 0, []incident.IncidentEvent{
		{IncidentID: ieInc, Kind: incident.EventAnalystCommented, At: ieBase.Add(time.Second), Actor: "a", Comment: "x"},
	}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale revision must conflict, got %v", err)
	}
	// Correct revision -> appended.
	if err := s.AppendEvents(ctx, ieInc, 1, []incident.IncidentEvent{
		{IncidentID: ieInc, Kind: incident.EventAnalystCommented, At: ieBase.Add(time.Second), Actor: "a", Comment: "x"},
	}); err != nil {
		t.Fatal(err)
	}
	events, err := s.LoadEvents(ctx, ieInc)
	if err != nil || len(events) != 2 {
		t.Fatalf("load: %d err=%v", len(events), err)
	}
	if _, err := incident.Project(events); err != nil {
		t.Fatalf("loaded log must project: %v", err)
	}
}

func TestIncidentEventStoreRejectsForeignEvent(t *testing.T) {
	s := NewIncidentEventStore()
	ctx := ieCtx(ieTenant)
	if err := s.AppendEvents(ctx, ieInc, 0, []incident.IncidentEvent{createdEvent("other-inc", ieAsset)}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("event for a different incident must be rejected, got %v", err)
	}
}

func TestIncidentEventStoreListAndTenantIsolation(t *testing.T) {
	s := NewIncidentEventStore()
	if err := s.AppendEvents(ieCtx(ieTenant), ieInc, 0, []incident.IncidentEvent{createdEvent(ieInc, ieAsset)}); err != nil {
		t.Fatal(err)
	}
	ids, err := s.ListIncidentIDs(ieCtx(ieTenant), ports.IncidentQuery{AssetID: ieAsset})
	if err != nil || len(ids) != 1 || ids[0] != ieInc {
		t.Fatalf("list by asset: %v err=%v", ids, err)
	}
	// Another tenant sees nothing, and cannot load the incident.
	other := shared.ID("tenant-other")
	if ids, _ := s.ListIncidentIDs(ieCtx(other), ports.IncidentQuery{}); len(ids) != 0 {
		t.Fatalf("cross-tenant list must be empty, got %d", len(ids))
	}
	if ev, _ := s.LoadEvents(ieCtx(other), ieInc); len(ev) != 0 {
		t.Fatalf("cross-tenant load must be empty, got %d", len(ev))
	}
	// Missing tenant fails closed.
	if err := s.AppendEvents(context.Background(), ieInc, 1, []incident.IncidentEvent{createdEvent(ieInc, ieAsset)}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("append without tenant must fail closed, got %v", err)
	}
}
