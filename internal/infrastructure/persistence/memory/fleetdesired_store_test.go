package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func desiredStoreState(tenant, assetID, policyID string, caps []string, version int64, now time.Time) *fleetdesired.State {
	return &fleetdesired.State{
		TenantID: shared.ID(tenant), AssetID: shared.ID(assetID), PolicyID: shared.ID(policyID), Capabilities: caps,
		UpdatedBy: "operator", Version: version, Audit: shared.Audit{CreatedAt: now, UpdatedAt: now},
	}
}

func TestFleetDesiredStoreTenantIsolationCopiesOrderingAndDelete(t *testing.T) {
	ctx := context.Background()
	store := NewFleetDesiredStore()
	now := time.Date(2026, 8, 19, 1, 2, 3, 0, time.UTC)
	for _, state := range []*fleetdesired.State{
		desiredStoreState("tenant-a", "asset-b", "policy-b", []string{"b"}, 1, now),
		desiredStoreState("tenant-a", "asset-a", "policy-a", []string{"a"}, 1, now),
		desiredStoreState("tenant-b", "asset-x", "policy-x", []string{"x"}, 1, now),
	} {
		if err := store.Put(ctx, state); err != nil {
			t.Fatal(err)
		}
	}

	rows, err := store.List(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].AssetID != "asset-a" || rows[1].AssetID != "asset-b" {
		t.Fatalf("unexpected deterministic tenant list: %#v", rows)
	}
	rows[0].Capabilities[0] = "mutated"
	got, err := store.Get(ctx, "tenant-a", "asset-a")
	if err != nil {
		t.Fatal(err)
	}
	if got.Capabilities[0] != "a" {
		t.Fatalf("caller mutated stored slice: %v", got.Capabilities)
	}
	if _, err := store.Get(ctx, "tenant-a", "asset-x"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant lookup = %v, want ErrNotFound", err)
	}
	if err := store.Delete(ctx, "tenant-a", "asset-a", "policy-a", 1); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, "tenant-a", "asset-a", "policy-a", 1); err != nil {
		t.Fatalf("idempotent delete failed: %v", err)
	}
	if _, err := store.Get(ctx, "tenant-a", "asset-a"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("deleted policy lookup=%v, want ErrNotFound", err)
	}
}

func TestFleetDesiredStoreUsesStructuredKeyNotDelimiterComposition(t *testing.T) {
	ctx := context.Background()
	store := NewFleetDesiredStore()
	now := time.Date(2026, 8, 19, 1, 2, 3, 0, time.UTC)
	first := desiredStoreState("a\x00b", "c", "policy-first", []string{"first"}, 1, now)
	second := desiredStoreState("a", "b\x00c", "policy-second", []string{"second"}, 1, now)
	if err := store.Put(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, second); err != nil {
		t.Fatal(err)
	}
	gotFirst, err := store.Get(ctx, first.TenantID, first.AssetID)
	if err != nil {
		t.Fatal(err)
	}
	gotSecond, err := store.Get(ctx, second.TenantID, second.AssetID)
	if err != nil {
		t.Fatal(err)
	}
	if gotFirst.Capabilities[0] != "first" || gotSecond.Capabilities[0] != "second" {
		t.Fatalf("structured keys collided: first=%+v second=%+v", gotFirst, gotSecond)
	}
}

func TestFleetDesiredStorePreservedCreatedAtCannotBreakTimeOrder(t *testing.T) {
	ctx := context.Background()
	store := NewFleetDesiredStore()
	created := time.Date(2026, 8, 19, 2, 0, 0, 0, time.UTC)
	initial := desiredStoreState("tenant", "asset", "policy", []string{"process"}, 1, created)
	if err := store.Put(ctx, initial); err != nil {
		t.Fatal(err)
	}
	older := created.Add(-time.Minute)
	update := desiredStoreState("tenant", "asset", "policy", []string{"network"}, 2, older)
	if err := store.Put(ctx, update); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("Put error=%v, want validation error", err)
	}
	got, err := store.Get(ctx, "tenant", "asset")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 || len(got.Capabilities) != 1 || got.Capabilities[0] != "process" {
		t.Fatalf("invalid update changed stored state: %+v", got)
	}
}

func TestFleetDesiredStoreCASRejectsStaleWritersAndDeletes(t *testing.T) {
	ctx := context.Background()
	store := NewFleetDesiredStore()
	now := time.Date(2026, 8, 19, 3, 0, 0, 0, time.UTC)
	v1 := desiredStoreState("tenant", "asset", "policy", []string{"process"}, 1, now)
	if err := store.Put(ctx, v1); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, desiredStoreState("tenant", "asset", "policy", []string{"network"}, 1, now)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate create error=%v, want ErrConflict", err)
	}

	v2 := desiredStoreState("tenant", "asset", "policy", []string{"network"}, 2, now.Add(time.Minute))
	v2.Audit.CreatedAt = now
	if err := store.Put(ctx, v2); err != nil {
		t.Fatal(err)
	}
	stale := desiredStoreState("tenant", "asset", "policy", []string{"file"}, 2, now.Add(2*time.Minute))
	stale.Audit.CreatedAt = now
	if err := store.Put(ctx, stale); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale update error=%v, want ErrConflict", err)
	}
	if err := store.Delete(ctx, "tenant", "asset", "policy", 1); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale delete error=%v, want ErrConflict", err)
	}
	got, err := store.Get(ctx, "tenant", "asset")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 2 || got.PolicyID != "policy" || len(got.Capabilities) != 1 || got.Capabilities[0] != "network" {
		t.Fatalf("stale operation changed newer policy: %+v", got)
	}
}
