package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/worksign"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetagentuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetwork"
)

// setupFleetVersion builds a fleet transport with a version-skew policy.
func setupFleetVersion(t *testing.T, minAgentVersion, cpVersion string) (http.Handler, *fleetagentuc.Service) {
	t.Helper()
	agentSvc, err := fleetagentuc.NewService(memory.NewFleetAgentStore(), ftAudit{}, ftClock{}, &ftIDs{})
	if err != nil {
		t.Fatalf("agent svc: %v", err)
	}
	signer, err := worksign.New([]byte("0123456789012345678901234567890123"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	workSvc, err := fleetwork.NewService(memory.NewWorkOrderStore(), signer, ftAudit{}, ftClock{}, &ftIDs{})
	if err != nil {
		t.Fatalf("work svc: %v", err)
	}
	rt := &Router{log: discardLog()}
	rt.SetFleet(agentSvc, workSvc, func() time.Time { return time.Now().UTC() }, "")
	rt.SetFleetAdmin(agentSvc)
	rt.SetFleetVersionPolicy(minAgentVersion, cpVersion)
	return rt.fleet.handler(), agentSvc
}

// enrolVersioned enrols an agent reporting agent_version and returns its token.
func enrolVersioned(t *testing.T, h http.Handler, agentSvc *fleetagentuc.Service, agentVersion string) string {
	t.Helper()
	tok, err := agentSvc.MintEnrolToken(t.Context(), "op", "default", time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/enrol", tok,
		map[string]any{"name": "agent-1", "platform": "linux", "agent_version": agentVersion}, true)
	if w.Code != http.StatusCreated {
		t.Fatalf("enrol should be 201, got %d (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Token == "" {
		t.Fatalf("enrol returned no token: %s", w.Body.String())
	}
	return resp.Token
}

func TestClaimRefusedBelowMinAgentVersion(t *testing.T) {
	h, agentSvc := setupFleetVersion(t, "1.0.0", "2.3.4")
	token := enrolVersioned(t, h, agentSvc, "0.9.0")

	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/work/claim", token, map[string]int{"max": 4}, true)
	if w.Code != http.StatusUpgradeRequired {
		t.Fatalf("an agent below the floor must get 426, got %d (%s)", w.Code, w.Body.String())
	}
	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["min_supported_agent_version"] != "1.0.0" || body["your_version"] != "0.9.0" || body["instruction"] == "" {
		t.Fatalf("refusal must state the floor, the agent version, and an instruction: %v", body)
	}
}

func TestClaimAllowedAtOrAboveFloor(t *testing.T) {
	h, agentSvc := setupFleetVersion(t, "1.0.0", "2.3.4")
	token := enrolVersioned(t, h, agentSvc, "1.2.0")
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/work/claim", token, map[string]int{"max": 4}, true)
	if w.Code != http.StatusOK {
		t.Fatalf("an agent at/above the floor must be allowed to claim, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestClaimFailClosedOnUnparseableVersionUnderFloor(t *testing.T) {
	h, agentSvc := setupFleetVersion(t, "1.0.0", "2.3.4")
	token := enrolVersioned(t, h, agentSvc, "") // no parseable version + active floor => refused
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/work/claim", token, map[string]int{"max": 4}, true)
	if w.Code != http.StatusUpgradeRequired {
		t.Fatalf("an agent with no parseable version under a floor must be refused, got %d", w.Code)
	}
}

func TestClaimNoFloorAllowsAnyVersion(t *testing.T) {
	h, agentSvc := setupFleetVersion(t, "", "2.3.4") // no floor
	token := enrolVersioned(t, h, agentSvc, "0.0.1")
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/work/claim", token, map[string]int{"max": 4}, true)
	if w.Code != http.StatusOK {
		t.Fatalf("with no floor any version may claim, got %d", w.Code)
	}
}

func TestHeartbeatAdvertisesVersionPolicy(t *testing.T) {
	h, agentSvc := setupFleetVersion(t, "1.0.0", "2.3.4")
	token := enrolVersioned(t, h, agentSvc, "1.2.0")
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/heartbeat", token,
		map[string]any{"platform": "linux", "agent_version": "1.2.0"}, true)
	if w.Code != http.StatusOK {
		t.Fatalf("heartbeat: %d (%s)", w.Code, w.Body.String())
	}
	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["control_plane_version"] != "2.3.4" || body["min_supported_agent_version"] != "1.0.0" {
		t.Fatalf("heartbeat must advertise cp version + floor, got %v", body)
	}
}
