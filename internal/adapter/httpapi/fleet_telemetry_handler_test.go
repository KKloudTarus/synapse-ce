package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/worksign"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/telemetryingest"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetagentuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetwork"
)

// setupFleetWithTelemetry builds the fleet transport plane with a real telemetry-ingest use case backed
// by the in-memory transport store, and a signing-key resolver holding one key. It returns the handler,
// the agent service (to enrol), the private key + keyID to sign manifests, and whether telemetry is wired.
func setupFleetWithTelemetry(t *testing.T, wireTelemetry bool) (http.Handler, *fleetagentuc.Service, ed25519.PrivateKey, func(agentID shared.ID) string) {
	t.Helper()
	agentSvc, err := fleetagentuc.NewService(memory.NewFleetAgentStore(), ftAudit{}, ftClock{}, &ftIDs{})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := worksign.New([]byte("0123456789012345678901234567890123"))
	if err != nil {
		t.Fatal(err)
	}
	workSvc, err := fleetwork.NewService(memory.NewWorkOrderStore(), signer, ftAudit{}, ftClock{}, &ftIDs{})
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// The key's AgentID is only known after enrol; keyOf builds a resolver-registered key for that agent.
	resolver := &lateResolver{}
	keyOf := func(agentID shared.ID) string {
		key, err := fleetagent.NewSigningKey(agentID, fleetagent.PurposeTelemetryBatch, pub, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		resolver.key = key
		return key.KeyID
	}
	ingest, err := telemetryingest.NewService(memory.NewTelemetryTransportStore(), resolver, ftAudit{}, ftClock{})
	if err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: discardLog()}
	rt.SetFleet(agentSvc, workSvc, func() time.Time { return time.Now().UTC() }, "")
	if wireTelemetry {
		rt.SetFleetTelemetry(ingest)
	}
	return rt.fleet.handler(), agentSvc, priv, keyOf
}

// lateResolver holds a key registered after enrol (once the agent id is known).
type lateResolver struct{ key fleetagent.AgentSigningKey }

func (r *lateResolver) ResolveSigningKey(_ context.Context, agentID shared.ID, keyID string) (fleetagent.AgentSigningKey, error) {
	if agentID == r.key.AgentID && keyID == r.key.KeyID {
		return r.key, nil
	}
	return fleetagent.AgentSigningKey{}, shared.ErrNotFound
}

func enrolAgent(t *testing.T, h http.Handler, agentSvc *fleetagentuc.Service) (token string, agentID shared.ID) {
	t.Helper()
	tok, err := agentSvc.MintEnrolToken(context.Background(), "op", "default", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/enrol", tok, map[string]any{"name": "tel-agent", "platform": "linux"}, true)
	if w.Code != http.StatusCreated {
		t.Fatalf("enrol should be 201, got %d (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		AgentID string `json:"agent_id"`
		Token   string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Token == "" || resp.AgentID == "" {
		t.Fatalf("enrol response: %v (%s)", err, w.Body.String())
	}
	return resp.Token, shared.ID(resp.AgentID)
}

func signedRequest(agentID shared.ID, keyID string, priv ed25519.PrivateKey) telemetryingest.IngestRequest {
	asset := shared.ID("asset-1")
	payload := []byte("event-bytes")
	m := fleetagent.TelemetryBatchManifest{
		ProtocolVersion:  fleetagent.TelemetryProtocolVersion,
		SchemaVersion:    1,
		BatchID:          "batch-1",
		AgentID:          agentID,
		AssetID:          asset,
		StreamID:         "stream-1",
		Position:         fleetagent.StreamPosition{Priority: fleetagent.PriorityP1, Epoch: 1, Sequence: 1, Session: "sess-1", Boot: "boot-1"},
		PreviousSequence: 0,
		EventTimeMin:     time.Unix(1_700_000_000, 0).UTC(),
		EventTimeMax:     time.Unix(1_700_000_001, 0).UTC(),
		ObservedCount:    1,
		KeptCount:        1,
		Events:           []fleetagent.EventRef{{ID: "e1", Digest: fleetagent.TelemetryEventDigest(payload, asset)}},
		KeyID:            keyID,
	}
	m.PayloadDigest = fleetagent.TelemetryPayloadDigest(m.Events)
	m.Signature = fleetagent.SignTelemetryManifest(priv, m)
	return telemetryingest.IngestRequest{
		Manifest: m,
		Events:   []telemetryingest.EventPayload{{EventID: "e1", Class: detection.ClassProcess, Payload: payload, ObservedAt: m.EventTimeMin}},
	}
}

func TestIngestTelemetryEndpointAccepts(t *testing.T) {
	h, agentSvc, priv, keyOf := setupFleetWithTelemetry(t, true)
	token, agentID := enrolAgent(t, h, agentSvc)
	req := signedRequest(agentID, keyOf(agentID), priv)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/telemetry", token, req, true)
	if w.Code != http.StatusOK {
		t.Fatalf("ingest should be 200, got %d (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Accepted bool   `json:"accepted"`
		ACK      uint64 `json:"ack"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || !resp.Accepted || resp.ACK != 1 {
		t.Fatalf("accept response: %+v err=%v (%s)", resp, err, w.Body.String())
	}
}

func TestIngestTelemetryEndpointIdentityMismatch403(t *testing.T) {
	h, agentSvc, priv, keyOf := setupFleetWithTelemetry(t, true)
	token, agentID := enrolAgent(t, h, agentSvc)
	// A manifest claiming a DIFFERENT agent than the authenticated credential must be forbidden.
	keyID := keyOf(agentID)
	req := signedRequest("someone-else", keyID, priv)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/telemetry", token, req, true)
	if w.Code != http.StatusForbidden {
		t.Fatalf("identity mismatch should be 403, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestIngestTelemetryEndpointNotEnabled404(t *testing.T) {
	h, agentSvc, priv, keyOf := setupFleetWithTelemetry(t, false) // telemetry not wired
	token, agentID := enrolAgent(t, h, agentSvc)
	req := signedRequest(agentID, keyOf(agentID), priv)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/telemetry", token, req, true)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unwired telemetry should be 404, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestIngestTelemetryEndpointRequiresAuth(t *testing.T) {
	h, _, _, _ := setupFleetWithTelemetry(t, true)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/telemetry", "", map[string]any{}, true)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no credential should be 401, got %d (%s)", w.Code, w.Body.String())
	}
}
