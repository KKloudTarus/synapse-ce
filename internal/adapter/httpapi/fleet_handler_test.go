package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetrollout"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/workorder"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/fleetca"
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

func (ftAudit) Record(context.Context, ports.AuditEntry) error     { return nil }
func (ftAudit) RecordOnce(context.Context, ports.AuditEntry) error { return nil }

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
	rt.SetFleet(agentSvc, workSvc, func() time.Time { return time.Now().UTC() }, "")
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
	if err := agentSvc.Revoke(ctx, "op", "default", agentID, "test revoke"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if w := fleetCall(h, http.MethodPost, "/api/v1/fleet/heartbeat", agentTok, map[string]string{}, true); w.Code != http.StatusForbidden {
		t.Fatalf("revoked agent should be 403, got %d", w.Code)
	}
}

func TestFleetAuthByClientCert(t *testing.T) {
	ctx := context.Background()
	// Real CA so the issued certificate parses and its fingerprint matches what the agent stores.
	caCertPEM, caKeyPEM, err := fleetca.GenerateCA("test-ca", time.Hour, time.Now())
	if err != nil {
		t.Fatalf("gen ca: %v", err)
	}
	ca, err := fleetca.New(caCertPEM, caKeyPEM, time.Hour)
	if err != nil {
		t.Fatalf("new ca: %v", err)
	}
	agentSvc, _ := fleetagentuc.NewService(memory.NewFleetAgentStore(), ftAudit{}, ftClock{}, &ftIDs{})
	agentSvc.SetCA(ca)

	enrolTok, _ := agentSvc.MintEnrolToken(ctx, "op", "default", time.Hour)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "agent"}}, key)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	agent, _, certPEM, err := agentSvc.Enrol(ctx, enrolTok, fleetagentuc.EnrolInput{Name: "a", CSRPEM: csrPEM})
	if err != nil || len(certPEM) == 0 {
		t.Fatalf("enrol with csr: err=%v certlen=%d", err, len(certPEM))
	}

	f := &fleetRouter{agents: agentSvc, clientCertHeader: "X-Client-Cert", log: discardLog()}

	// The issued certificate authenticates the agent.
	got, err := f.authByClientCert(ctx, string(certPEM))
	if err != nil || got.ID != agent.ID {
		t.Fatalf("cert auth should succeed: got=%v err=%v", got, err)
	}
	// A malformed header is unauthenticated, never a 500.
	if _, err := f.authByClientCert(ctx, "not a cert"); !errors.Is(err, fleetagentuc.ErrUnauthenticated) {
		t.Fatalf("malformed cert must be unauthenticated, got %v", err)
	}
	// After revocation the certificate no longer authenticates.
	if err := agentSvc.Revoke(ctx, "op", "default", agent.ID, "test"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := f.authByClientCert(ctx, string(certPEM)); !errors.Is(err, fleetagentuc.ErrRevoked) {
		t.Fatalf("revoked cert must return ErrRevoked, got %v", err)
	}
}

func TestFleetAuthByClientCertRejectsExpired(t *testing.T) {
	ctx := context.Background()
	agentSvc, _ := fleetagentuc.NewService(memory.NewFleetAgentStore(), ftAudit{}, ftClock{}, &ftIDs{})
	f := &fleetRouter{agents: agentSvc, clientCertHeader: "X-Client-Cert", log: discardLog()}

	// A self-signed certificate whose validity window is entirely in the past.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ag", OrganizationalUnit: []string{"default"}},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(-1 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	// Expiry is rejected before any store lookup, so the result is unauthenticated.
	if _, err := f.authByClientCert(ctx, string(certPEM)); !errors.Is(err, fleetagentuc.ErrUnauthenticated) {
		t.Fatalf("expired certificate must be unauthenticated, got %v", err)
	}
}

// TestHeartbeatOffersNoUpdateWithoutARolloutService is the fail-closed default that matters most: the
// absence of a rollout decider must never read as permission to replace a binary on someone's host.
func TestHeartbeatOffersNoUpdateWithoutARolloutService(t *testing.T) {
	t.Parallel()

	f := &fleetRouter{}
	offer := f.updateOffer(context.Background(), &fleetagent.Agent{TenantID: "t1"}, "1.0.0")
	if offer["available"] != false {
		t.Fatalf("no rollout service must offer nothing, got %+v", offer)
	}
	if offer["reason"] == "" || offer["reason"] == nil {
		t.Fatal("a declined offer must explain itself")
	}
	if _, named := offer["target_version"]; named {
		t.Fatal("a declined offer must not name a target version")
	}
}

// The offer is computed from the agent's OPERATOR-ASSIGNED group, never from anything the agent just
// reported. An agent that could choose its own group could pin itself to an older, vulnerable version.
func TestHeartbeatOfferUsesTheStoredGroup(t *testing.T) {
	t.Parallel()

	f := &fleetRouter{rollout: stubRollout{canary: "canary", target: "2.0.0"}}

	inCanary := f.updateOffer(context.Background(), &fleetagent.Agent{TenantID: "t1", Group: "canary"}, "1.0.0")
	if inCanary["available"] != true || inCanary["target_version"] != "2.0.0" {
		t.Fatalf("an agent in the canary group must be offered the target, got %+v", inCanary)
	}
	outside := f.updateOffer(context.Background(), &fleetagent.Agent{TenantID: "t1", Group: "prod"}, "1.0.0")
	if outside["available"] != false {
		t.Fatalf("an agent outside the canary must not be offered the target, got %+v", outside)
	}
}

type stubRollout struct{ canary, target string }

func (s stubRollout) DecideFor(_ context.Context, _ shared.ID, _, group, _ string) fleetrollout.Decision {
	if group == s.canary {
		return fleetrollout.Decision{Offer: true, Target: s.target, Reason: fleetrollout.ReasonCanary}
	}
	return fleetrollout.Decision{Reason: fleetrollout.ReasonCanaryOnly}
}

// TestFleetDecommission exercises the agent-self clean-uninstall report (#412, AC 11): an authenticated
// agent decommissions itself, and its credential then stops authenticating (403 decommissioned) on any
// further transport call.
func TestFleetDecommission(t *testing.T) {
	h, agentSvc, _ := setupFleet(t)
	ctx := context.Background()

	enrolTok, err := agentSvc.MintEnrolToken(ctx, "op", "default", time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/enrol", enrolTok, map[string]any{"name": "agent-x", "platform": "linux"}, true)
	if w.Code != http.StatusCreated {
		t.Fatalf("enrol should be 201, got %d (%s)", w.Code, w.Body.String())
	}
	var enrolResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &enrolResp); err != nil {
		t.Fatalf("enrol resp: %v", err)
	}
	agentTok := enrolResp.Token

	// Decommission requires auth.
	if w := fleetCall(h, http.MethodPost, "/api/v1/fleet/decommission", "", nil, true); w.Code != http.StatusUnauthorized {
		t.Fatalf("decommission without auth should be 401, got %d", w.Code)
	}
	// A healthy agent decommissions itself.
	if w := fleetCall(h, http.MethodPost, "/api/v1/fleet/decommission", agentTok, nil, true); w.Code != http.StatusOK {
		t.Fatalf("decommission should be 200, got %d (%s)", w.Code, w.Body.String())
	}
	// Its credential no longer authenticates anywhere on the transport.
	if w := fleetCall(h, http.MethodPost, "/api/v1/fleet/heartbeat", agentTok, map[string]string{"agent_version": "0.2.0"}, true); w.Code != http.StatusForbidden {
		t.Fatalf("decommissioned agent heartbeat should be 403, got %d (%s)", w.Code, w.Body.String())
	}
	if w := fleetCall(h, http.MethodPost, "/api/v1/fleet/decommission", agentTok, nil, true); w.Code != http.StatusForbidden {
		t.Fatalf("re-decommission after decommission should be 403, got %d", w.Code)
	}
}
