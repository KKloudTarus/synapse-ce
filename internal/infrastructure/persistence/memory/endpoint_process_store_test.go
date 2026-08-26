package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func snap(tenant, asset, entity string, running bool) ports.ProcessSnapshot {
	return ports.ProcessSnapshot{
		TenantID: shared.ID(tenant), AssetID: shared.ID(asset), EntityID: shared.ID(entity),
		PID: 100, Comm: "curl", Path: "/usr/bin/curl", Running: running, LastSeenAt: time.Unix(1_700_000_000, 0).UTC(),
	}
}

func TestEndpointProcessStoreSaveListAndRunningFilter(t *testing.T) {
	s := NewEndpointProcessStore()
	ctx := shared.WithTenant(context.Background(), "ta")
	if err := s.SaveProcesses(ctx, []ports.ProcessSnapshot{
		snap("ta", "host-1", "e1", true),
		snap("ta", "host-1", "e2", false), // exited
		snap("ta", "host-1", "e3", true),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListRunningByAsset(ctx, "host-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].EntityID != "e1" || got[1].EntityID != "e3" {
		t.Fatalf("running filter/order wrong: %+v", got)
	}
	// Upsert e1 to exited -> drops out of the running list.
	if err := s.SaveProcesses(ctx, []ports.ProcessSnapshot{snap("ta", "host-1", "e1", false)}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.ListRunningByAsset(ctx, "host-1")
	if len(got) != 1 || got[0].EntityID != "e3" {
		t.Fatalf("upsert to exited must drop from running, got %+v", got)
	}
}

func TestEndpointProcessStoreTenantIsolation(t *testing.T) {
	s := NewEndpointProcessStore()
	ctxA := shared.WithTenant(context.Background(), "ta")
	ctxB := shared.WithTenant(context.Background(), "tb")
	if err := s.SaveProcesses(ctxA, []ports.ProcessSnapshot{snap("ta", "host-1", "e1", true)}); err != nil {
		t.Fatal(err)
	}
	// Tenant B sees nothing for the same asset id.
	if got, _ := s.ListRunningByAsset(ctxB, "host-1"); len(got) != 0 {
		t.Fatalf("tenant B must not see A's processes, got %d", len(got))
	}
	// A snapshot whose tenant disagrees with the ctx tenant is rejected.
	if err := s.SaveProcesses(ctxA, []ports.ProcessSnapshot{snap("tb", "host-1", "e1", true)}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("cross-tenant snapshot must be rejected, got %v", err)
	}
	// No tenant in context is rejected.
	if err := s.SaveProcesses(context.Background(), []ports.ProcessSnapshot{snap("ta", "host-1", "e1", true)}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing tenant must be rejected, got %v", err)
	}
	if _, err := s.ListRunningByAsset(context.Background(), "host-1"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("list without tenant must be rejected, got %v", err)
	}
}

func TestEndpointProcessStoreValidation(t *testing.T) {
	s := NewEndpointProcessStore()
	ctx := shared.WithTenant(context.Background(), "ta")
	bad := snap("ta", "host-1", "", true) // missing entity id
	if err := s.SaveProcesses(ctx, []ports.ProcessSnapshot{bad}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing entity id must be rejected, got %v", err)
	}
	if err := s.SaveProcesses(ctx, nil); err != nil {
		t.Fatalf("saving zero snapshots must be a no-op, got %v", err)
	}
}
