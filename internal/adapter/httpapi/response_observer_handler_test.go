package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	responseobserveruc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/responseobserver"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetagentuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type responseObserverAdminStub struct {
	input responseobserveruc.AssignInput
}

func (s *responseObserverAdminStub) Assign(_ context.Context, input responseobserveruc.AssignInput) (fleetagent.ResponseObserverBinding, error) {
	s.input = input
	return fleetagent.ResponseObserverBinding{
		TenantID: input.TenantID, AgentID: input.AgentID, AssetID: input.AssetID, AssignedBy: input.Actor,
		AssignedAt: time.Unix(2_000_000, 0).UTC(), ExpiresAt: input.ExpiresAt, Version: input.ExpectedVersion + 1,
	}, nil
}

func TestAssignResponseObserverUsesAuthenticatedActorAndPathIdentity(t *testing.T) {
	expiresAt := time.Unix(2_003_600, 0).UTC()
	body, err := json.Marshal(map[string]any{
		"expires_at": expiresAt, "expected_version": 0, "assigned_by": "attacker",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/api/v1/fleet/assets/asset-1/response-observers/observer-1", bytes.NewReader(body))
	request.SetPathValue("id", "asset-1")
	request.SetPathValue("agentID", "observer-1")
	ctx := context.WithValue(request.Context(), principalKey, Principal{ID: "operator-1", Role: "admin", TenantID: "tenant-1"})
	request = request.WithContext(shared.WithTenant(ctx, "tenant-1"))
	stub := &responseObserverAdminStub{}
	router := &Router{log: discardLog(), responseObservers: stub}
	response := httptest.NewRecorder()
	router.assignResponseObserver(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if stub.input.TenantID != "tenant-1" || stub.input.AgentID != "observer-1" || stub.input.AssetID != "asset-1" ||
		stub.input.Actor != "operator-1" || stub.input.ExpectedVersion != 0 || !stub.input.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("assignment input=%+v", stub.input)
	}
}

func TestHeartbeatReturnsOnlyActiveServerOwnedObserverAssignment(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	ctx := shared.WithTenant(context.Background(), "tenant-1")
	agentStore := memory.NewFleetAgentStore()
	agent, err := fleetagent.NewAgent(
		"observer-1", "tenant-1", "observer", "linux", "test", "test",
		[]string{workorder.CapabilityResponseObserve}, "token-hash", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := agentStore.CreateAgent(ctx, agent); err != nil {
		t.Fatal(err)
	}
	agentService, err := fleetagentuc.NewService(agentStore, ftAudit{}, ftClock{}, &ftIDs{})
	if err != nil {
		t.Fatal(err)
	}
	bindingStore := memory.NewResponseObserverBindingStore()
	binding := fleetagent.ResponseObserverBinding{
		TenantID: "tenant-1", AgentID: agent.ID, AssetID: "asset-1", AssignedBy: "operator-1",
		AssignedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Version: 1,
	}
	intentID := "observer-assignment:observer-1"
	if _, _, err := bindingStore.SaveResponseObserverBindingWithAudit(ctx, binding, 0, ports.FleetAuditIntent{
		ID: intentID, Entry: ports.AuditEntry{
			Actor: "operator-1", Action: "fleet.response_observer.assigned", Target: agent.ID.String(), At: binding.AssignedAt,
			Metadata: map[string]string{"idempotency_key": intentID},
		},
	}); err != nil {
		t.Fatal(err)
	}
	fleet := &fleetRouter{agents: agentService, responseObservers: bindingStore, now: func() time.Time { return now }, log: discardLog()}
	body := bytes.NewBufferString(`{"platform":"linux","agent_version":"test","capabilities":["response.observe"]}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/heartbeat", body)
	request = request.WithContext(context.WithValue(ctx, agentKeyCtx, agent))
	response := httptest.NewRecorder()
	fleet.heartbeat(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["response_observer_asset_id"] != "asset-1" {
		t.Fatalf("heartbeat payload=%+v", payload)
	}
}
