package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/processreport"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetagentuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestProcessReportIngestPersistsAndResolvesServerSide drives the agent-plane process report end to end
// through the real agent auth: an enrolled agent whose host asset is bound reports its running
// processes, the server resolves the asset from the agent (never the request), and the projection is
// saved under the agent's tenant.
func TestProcessReportIngestPersistsAndResolvesServerSide(t *testing.T) {
	h, agentSvc, _ := setupFleetWithIngest(t)
	token := enrolAgentToken(t, h, agentSvc)

	// Bind the enrolled agent to a host asset, the prerequisite the real flow satisfies by reporting
	// inventory first. The agent id the enrol minted is the token's subject; resolve it from the store.
	bindings := memory.NewTelemetryTransportStore()
	procStore := memory.NewEndpointProcessStore()
	agentID := onlyAgentID(t, agentSvc)
	if err := bindings.BindTelemetryAsset(shared.WithTenant(context.Background(), "default"),
		ports.TelemetryAssetBinding{TenantID: "default", AgentID: agentID, AssetID: "host-asset-1", UpdatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	svc, err := processreport.NewService(bindings, procStore, nil, ftClock{})
	if err != nil {
		t.Fatalf("process report svc: %v", err)
	}
	// Re-wire a fleet router carrying the process-report service (setupFleetWithIngest does not).
	rt := &Router{log: discardLog()}
	rt.SetFleet(agentSvc, nil, func() time.Time { return time.Now().UTC() }, "")
	rt.SetFleetProcessReport(svc)
	handler := rt.fleet.handler()

	body := map[string]any{"processes": []map[string]any{
		{"pid": 1, "comm": "systemd", "path": "/usr/lib/systemd/systemd", "running": true},
		{"pid": 42, "comm": "sshd", "path": "/usr/sbin/sshd", "running": true},
	}}
	w := fleetCall(handler, http.MethodPost, "/api/v1/fleet/processes", token, body, true)
	if w.Code != http.StatusOK {
		t.Fatalf("process report should be 200, got %d (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		AssetID string `json:"asset_id"`
		Saved   int    `json:"saved"`
		Learned bool   `json:"learned"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if resp.AssetID != "host-asset-1" || resp.Saved != 2 || resp.Learned {
		t.Fatalf("resp = %+v, want host-asset-1 / 2 saved / not learned (no learner)", resp)
	}
	running, err := procStore.ListRunningByAsset(shared.WithTenant(context.Background(), "default"), "host-asset-1")
	if err != nil {
		t.Fatalf("list running: %v", err)
	}
	if len(running) != 2 {
		t.Fatalf("the running-process projection must hold both processes, got %d", len(running))
	}
}

// TestProcessReportRejectsAnUnboundAgent: an agent that has not reported inventory has no asset binding,
// so the report is refused (validation), not silently accepted.
func TestProcessReportRejectsAnUnboundAgent(t *testing.T) {
	h, agentSvc, _ := setupFleetWithIngest(t)
	token := enrolAgentToken(t, h, agentSvc)
	svc, err := processreport.NewService(memory.NewTelemetryTransportStore(), memory.NewEndpointProcessStore(), nil, ftClock{})
	if err != nil {
		t.Fatalf("svc: %v", err)
	}
	rt := &Router{log: discardLog()}
	rt.SetFleet(agentSvc, nil, func() time.Time { return time.Now().UTC() }, "")
	rt.SetFleetProcessReport(svc)
	handler := rt.fleet.handler()

	w := fleetCall(handler, http.MethodPost, "/api/v1/fleet/processes", token,
		map[string]any{"processes": []map[string]any{{"pid": 1, "comm": "x"}}}, true)
	if w.Code == http.StatusOK {
		t.Fatalf("an unbound agent's report must not be accepted, got %d (%s)", w.Code, w.Body.String())
	}
}

// TestProcessReportRouteAbsentWhenUnwired: without the service the route is a 404, consistent with every
// other optional fleet ingest.
func TestProcessReportRouteAbsentWhenUnwired(t *testing.T) {
	h, agentSvc, _ := setupFleetWithIngest(t) // does not wire process report
	token := enrolAgentToken(t, h, agentSvc)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/processes", token,
		map[string]any{"processes": []map[string]any{{"pid": 1}}}, true)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unwired process route should be 404, got %d (%s)", w.Code, w.Body.String())
	}
}

// onlyAgentID returns the single enrolled agent's id, so a test can bind it without knowing the minted id.
func onlyAgentID(t *testing.T, agentSvc *fleetagentuc.Service) shared.ID {
	t.Helper()
	agents, err := agentSvc.ListAgents(shared.WithTenant(context.Background(), "default"), "default")
	if err != nil {
		t.Fatalf("list agents: %v", err)
	}
	if len(agents) != 1 {
		t.Fatalf("want exactly one enrolled agent, got %d", len(agents))
	}
	return agents[0].ID
}
