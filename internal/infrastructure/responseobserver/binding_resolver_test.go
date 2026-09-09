package responseobserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type resolverClock struct{ now time.Time }

func (c resolverClock) Now() time.Time { return c.now }

func saveObserverBinding(t *testing.T, ctx context.Context, store *memory.ResponseObserverBindingStore, binding fleetagent.ResponseObserverBinding) {
	t.Helper()
	intentID := "observer-binding:" + binding.AgentID.String()
	_, _, err := store.SaveResponseObserverBindingWithAudit(ctx, binding, 0, ports.FleetAuditIntent{
		ID: intentID,
		Entry: ports.AuditEntry{
			Actor: binding.AssignedBy, Action: "fleet.response_observer.assigned", Target: binding.AgentID.String(), At: binding.AssignedAt,
			Metadata: map[string]string{"idempotency_key": intentID},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBindingResolverAuthorizesOnlyLiveBoundObserverTarget(t *testing.T) {
	now := time.Unix(2_000_000, 0).UTC()
	ctx := shared.WithTenant(context.Background(), "tenant-1")
	primary := memory.NewTelemetryTransportStore()
	if err := primary.BindTelemetryAsset(ctx, ports.TelemetryAssetBinding{
		TenantID: "tenant-1", AgentID: "observer-1", AssetID: "observer-host", UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	observers := memory.NewResponseObserverBindingStore()
	saveObserverBinding(t, ctx, observers, fleetagent.ResponseObserverBinding{
		TenantID: "tenant-1", AgentID: "observer-1", AssetID: "target-asset", AssignedBy: "operator-1",
		AssignedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), Version: 1,
	})
	resolver, err := NewBindingResolver(primary, observers, resolverClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	primaryAsset, err := resolver.ResolveTelemetryAsset(ctx, "observer-1")
	if err != nil || primaryAsset != "observer-host" {
		t.Fatalf("observer primary telemetry asset=%q err=%v", primaryAsset, err)
	}
	targetAsset, err := resolver.ResolveResponseObservationAsset(ctx, "observer-1")
	if err != nil || targetAsset != "target-asset" {
		t.Fatalf("observer target asset=%q err=%v", targetAsset, err)
	}
	otherTenant := shared.WithTenant(context.Background(), "tenant-2")
	if _, err := resolver.ResolveResponseObservationAsset(otherTenant, "observer-1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant observer error=%v", err)
	}
	expired, err := NewBindingResolver(primary, observers, resolverClock{now: now.Add(2 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := expired.ResolveResponseObservationAsset(ctx, "observer-1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("expired observer error=%v", err)
	}
}

func TestBindingResolverRefusesObserverWithoutPrimaryHostBinding(t *testing.T) {
	now := time.Unix(2_000_000, 0).UTC()
	ctx := shared.WithTenant(context.Background(), "tenant-1")
	observers := memory.NewResponseObserverBindingStore()
	saveObserverBinding(t, ctx, observers, fleetagent.ResponseObserverBinding{
		TenantID: "tenant-1", AgentID: "observer-1", AssetID: "target-asset", AssignedBy: "operator-1",
		AssignedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), Version: 1,
	})
	resolver, err := NewBindingResolver(memory.NewTelemetryTransportStore(), observers, resolverClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveResponseObservationAsset(ctx, "observer-1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unbound observer error=%v", err)
	}
}
