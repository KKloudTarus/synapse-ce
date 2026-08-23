package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestTelemetryAssetBindingRejectsCrossAgentTakeover(t *testing.T) {
	store := NewTelemetryTransportStore()
	tenant := shared.ID("tenant-asset-binding")
	ctx := shared.WithTenant(context.Background(), tenant)
	now := time.Unix(1700000000, 0).UTC()

	first := ports.TelemetryAssetBinding{
		TenantID: tenant,
		AgentID: "agent-a",
		AssetID: "asset-1",
		UpdatedAt: now,
	}
	if err := store.BindTelemetryAsset(ctx, first); err != nil {
		t.Fatalf("bind initial asset: %v", err)
	}
	second := ports.TelemetryAssetBinding{
		TenantID: tenant,
		AgentID: "agent-b",
		AssetID: "asset-1",
		UpdatedAt: now.Add(time.Second),
	}
	if err := store.BindTelemetryAsset(ctx, second); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("cross-agent takeover error = %v, want conflict", err)
	}

	assetID, err := store.ResolveTelemetryAsset(ctx, "agent-a")
	if err != nil || assetID != "asset-1" {
		t.Fatalf("original binding = %q, %v; want asset-1", assetID, err)
	}
	if _, err := store.ResolveTelemetryAsset(ctx, "agent-b"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("rejected agent unexpectedly acquired binding: %v", err)
	}
}
