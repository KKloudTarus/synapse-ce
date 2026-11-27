package httpapi

import (
	"context"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	responseobserveruc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/responseobserver"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// The response observer seed gives tenantA an asset whose primary telemetry agent is one agent and an
// independent, active observer agent that advertises response.observe, so assigning the observer is a
// request tenantA can make succeed and tenantB, at the same path, cannot.
const (
	responseObserverAsset    = shared.ID("harness-observed-asset-A")
	responseObserverPrimary  = shared.ID("harness-primary-agent-A")
	responseObserverObserver = shared.ID("harness-observer-agent-A")
)

func init() {
	route := "PUT /api/v1/fleet/assets/{id}/response-observers/{agentID}"
	registerHarnessSeed(harnessSeed{
		Name: "response observer",
		RoutePathValues: map[string]map[string]string{
			route: {"{id}": responseObserverAsset.String(), "{agentID}": responseObserverObserver.String()},
		},
		Run: seedResponseObserver,
	})
	// The service refuses an expiry outside its window measured from the seed's fixed clock.
	expires := engmiscNow.Add(time.Hour).UTC().Format(time.RFC3339)
	harnessWriteRequests[route] = harnessWriteRequest{
		body:        fmt.Sprintf(`{"expires_at":%q,"expected_version":0}`, expires),
		tenantBound: true,
	}
}

func seedResponseObserver(w *harnessWorld) []string {
	w.t.Helper()
	ctx := shared.WithTenant(context.Background(), "tenantA")
	agents := memory.NewFleetAgentStore()
	for _, agent := range []*fleetagent.Agent{
		{ID: responseObserverPrimary, TenantID: "tenantA", Name: "primary", State: fleetagent.StateActive},
		{ID: responseObserverObserver, TenantID: "tenantA", Name: "observer", State: fleetagent.StateActive, Capabilities: []string{workorder.CapabilityResponseObserve}},
	} {
		if err := agents.CreateAgent(ctx, agent); err != nil {
			w.t.Fatalf("seed agent %s: %v", agent.ID, err)
		}
	}
	telemetry := memory.NewTelemetryTransportStore()
	if err := telemetry.BindTelemetryAsset(ctx, ports.TelemetryAssetBinding{TenantID: "tenantA", AgentID: responseObserverPrimary, AssetID: responseObserverAsset, UpdatedAt: engmiscNow}); err != nil {
		w.t.Fatalf("seed primary telemetry binding: %v", err)
	}
	service, err := responseobserveruc.NewService(memory.NewResponseObserverBindingStore(), agents, telemetry, &harnessAudit{}, engmiscClock{})
	if err != nil {
		w.t.Fatalf("response observer service: %v", err)
	}
	w.rt.SetResponseObserverAdmin(service)
	return nil
}
