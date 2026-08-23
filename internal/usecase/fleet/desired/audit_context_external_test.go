package fleetdesired_test

import (
	"context"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	desireduc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/desired"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type tenantCapturingAudit struct {
	tenants []shared.ID
}

func (a *tenantCapturingAudit) Record(ctx context.Context, _ ports.AuditEntry) error {
	tenantID, _ := shared.TenantFrom(ctx)
	a.tenants = append(a.tenants, tenantID)
	return nil
}

func TestDesiredMutationBindsAuditToPolicyTenant(t *testing.T) {
	ctx := shared.WithTenant(context.Background(), "wrong-tenant")
	now := time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC)
	store := memory.NewFleetDesiredStore()
	audit := &tenantCapturingAudit{}
	svc := newTestService(t, store,
		&testAssets{rows: map[shared.ID]*asset.Asset{"asset-1": technicalAsset("asset-1", asset.KindHost)}},
		&testBindings{}, &testAgents{}, audit, &testClock{now: now}, time.Minute)

	if _, err := svc.SetDesiredCapabilities(ctx, desireduc.SetInput{
		TenantID: "tenant-1", AssetID: "asset-1", Actor: "operator", Capabilities: []string{"process"},
	}); err != nil {
		t.Fatalf("set desired capabilities: %v", err)
	}
	if len(audit.tenants) != 1 || audit.tenants[0] != "tenant-1" {
		t.Fatalf("set audit tenant=%v, want [tenant-1]", audit.tenants)
	}

	if err := svc.ClearDesiredCapabilities(context.Background(), desireduc.ClearInput{
		TenantID: "tenant-1", AssetID: "asset-1", Actor: "operator",
	}); err != nil {
		t.Fatalf("clear desired capabilities: %v", err)
	}
	if len(audit.tenants) != 2 || audit.tenants[1] != "tenant-1" {
		t.Fatalf("clear audit tenants=%v, want both tenant-1", audit.tenants)
	}
}
