package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/worksign"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetagentuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetwork"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type ftClock struct{}

func (ftClock) Now() time.Time { return time.Now().UTC() }

type ftIDs struct{ n int }

func (g *ftIDs) NewID() shared.ID { g.n++; return shared.ID(fmt.Sprintf("fid-%d", g.n)) }

type ftAudit struct{}

func (ftAudit) Record(context.Context, ports.AuditEntry) error { return nil }

func setupFleet(t *testing.T) (http.Handler, *fleetagentuc.Service, *fleetwork.Service) {
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
	rt.SetFleet(agentSvc, workSvc, func() time.Time { return time.Now().UTC() })
	rt.SetFleetAdmin(agentSvc)
	return rt.fleet.handler(), agentSvc, workSvc
}

func fleetCall(h http.Handler, method, path, token string, body any, proto bool) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	if proto {
		req.Header.Set("X-Synapse-Fleet-Proto", "1")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestFleetAPIEndToEnd(t *testing.T) {
	h, agentSvc, workSvc := setupFleet(t)
	ctx := context.Background()

	// Version required.
	if w := fleetCall(h, http.MethodPost, "/api/v1/fleet/enrol", "", map[string]string{"name": "a"}, false); w.Code != http.StatusBadRequest {
		t.Fatalf("missing proto header should be 400, got %d", w.Code)
	}

	// Mint an enrolment token (operator action, done directly here).
	enrolTok, err := agentSvc.MintEnrolToken(ctx, "op", "default", time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// Enrol.
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/enrol", enrolTok, map[string]any{"name": "agent-1", "platform": "linux"}, true)
	if w.Code != http.StatusCreated {
		t.Fatalf("enrol should be 201, got %d (%s)", w.Code, w.Body.String())
	}
	var enrolResp struct {
		AgentID string `json:"agent_id"`
		Token   string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &enrolResp); err != nil {
		t.Fatalf("enrol resp: %v", err)
	}
	if enrolResp.AgentID == "" || enrolResp.Token == "" {
		t.Fatalf("enrol must return agent id + token")
	}
	agentTok := enrolResp.Token
	agentID := shared.ID(enrolResp.AgentID)

	// Heartbeat requires auth.
	if w := fleetCall(h, http.MethodPost, "/api/v1/fleet/heartbeat", "", nil, true); w.Code != http.StatusUnauthorized {
		t.Fatalf("heartbeat without auth should be 401, got %d", w.Code)
	}
	if w := fleetCall(h, http.MethodPost, "/api/v1/fleet/heartbeat", agentTok, map[string]string{"agent_version": "0.2.0"}, true); w.Code != http.StatusOK {
		t.Fatalf("heartbeat should be 200, got %d", w.Code)
	}

	// Issue a work order addressed to this agent, then claim it over the API.
	issue := func(agent shared.ID, idem string, bucket int64) *workorder.WorkOrder {
		wo, err := workSvc.Issue(ctx, "op", fleetwork.IssueInput{
			TenantID: "default", AssetID: "as1", AgentID: agent, Capability: "scan.source",
			AuthorizationID: "eng1", IdempotencyKey: idem, NotAfter: time.Now().Add(time.Hour), TimeBucket: bucket,
		})
		if err != nil {
			t.Fatalf("issue %s: %v", idem, err)
		}
		return wo
	}
	mine := issue(agentID, "idem-mine", 1)
	other := issue("other-agent", "idem-other", 2)

	// Claim returns only the order addressed to this agent.
	w = fleetCall(h, http.MethodPost, "/api/v1/fleet/work/claim", agentTok, map[string]int{"max": 10}, true)
	if w.Code != http.StatusOK {
		t.Fatalf("claim should be 200, got %d", w.Code)
	}
	var claimed []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &claimed); err != nil {
		t.Fatalf("claim resp: %v", err)
	}
	if len(claimed) != 1 || claimed[0]["ID"] != mine.ID.String() {
		t.Fatalf("claim must return only the addressed order, got %v", claimed)
	}

	// Progress claimed -> running, then result running -> succeeded, idempotent on repeat.
	if w := fleetCall(h, http.MethodPost, "/api/v1/fleet/work/"+mine.ID.String()+"/progress", agentTok, nil, true); w.Code != http.StatusOK {
		t.Fatalf("progress should be 200, got %d (%s)", w.Code, w.Body.String())
	}
	if w := fleetCall(h, http.MethodPost, "/api/v1/fleet/work/"+mine.ID.String()+"/result", agentTok, map[string]string{"status": "succeeded"}, true); w.Code != http.StatusOK {
		t.Fatalf("result should be 200, got %d (%s)", w.Code, w.Body.String())
	}
	if w := fleetCall(h, http.MethodPost, "/api/v1/fleet/work/"+mine.ID.String()+"/result", agentTok, map[string]string{"status": "succeeded"}, true); w.Code != http.StatusOK {
		t.Fatalf("repeat result should be idempotent 200, got %d", w.Code)
	}

	// An order addressed to another agent is not_found for us (no existence leak).
	if w := fleetCall(h, http.MethodPost, "/api/v1/fleet/work/"+other.ID.String()+"/result", agentTok, map[string]string{"status": "succeeded"}, true); w.Code != http.StatusNotFound {
		t.Fatalf("mis-addressed order must be 404, got %d", w.Code)
	}

	// Revoke the agent; its credential no longer authenticates.
	if err := agentSvc.Revoke(ctx, "op", "default", agentID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if w := fleetCall(h, http.MethodPost, "/api/v1/fleet/heartbeat", agentTok, map[string]string{}, true); w.Code != http.StatusForbidden {
		t.Fatalf("revoked agent should be 403, got %d", w.Code)
	}
}
