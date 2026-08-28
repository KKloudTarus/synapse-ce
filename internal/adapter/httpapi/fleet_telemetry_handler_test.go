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
	"github.com/KKloudTarus/synapse-ce/internal/domain/privacy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/worksign"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/telemetryingest"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetagentuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetwork"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func setupFleetWithTelemetry(t *testing.T, wireTelemetry bool) (http.Handler, *fleetagentuc.Service, ed25519.PrivateKey, func(agentID shared.ID) string, string) {
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
	resolver := &lateResolver{}
	transport := memory.NewTelemetryTransportStore()
	policies := memory.NewPrivacyPolicyStore()
	policyAssignment, err := privacy.NewAssignment(
		"default",
		privacy.DefaultPolicy(),
		"test-operator",
		time.Unix(1_700_000_000, 0).UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	policyCtx := shared.WithTenant(context.Background(), "default")
	if _, err := policies.PutPrivacyPolicy(policyCtx, policyAssignment); err != nil {
		t.Fatal(err)
	}
	if _, err := policies.ActivatePrivacyPolicy(policyCtx, privacy.Activation{
		TenantID: "default", OperationID: "activate-default", PolicyDigest: policyAssignment.Digest,
		PolicyVersion: policyAssignment.Policy.Version, ActivatedBy: "test-operator",
		ActivatedAt: time.Unix(1_700_000_000, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	keyOf := func(agentID shared.ID) string {
		key, err := fleetagent.NewSigningKey(agentID, fleetagent.PurposeTelemetryBatch, pub, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		resolver.key = key
		ctx := shared.WithTenant(context.Background(), shared.ID("default"))
		if err := transport.BindTelemetryAsset(ctx, ports.TelemetryAssetBinding{TenantID: "default", AgentID: agentID, AssetID: "asset-1", UpdatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		return key.KeyID
	}
	ingest, err := telemetryingest.NewService(transport, resolver, policies, ftAudit{}, ftClock{})
	if err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: discardLog()}
	rt.SetFleet(agentSvc, workSvc, func() time.Time { return time.Now().UTC() }, "")
	if wireTelemetry {
		rt.SetFleetTelemetry(ingest)
	}
	return rt.fleet.handler(), agentSvc, priv, keyOf, policyAssignment.Digest
}

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

func signedRequest(t *testing.T, agentID shared.ID, keyID string, policyDigest string, priv ed25519.PrivateKey) telemetryingest.IngestRequest {
	t.Helper()
	asset := shared.ID("asset-1")
	session := fleetagent.CanonicalSessionID(agentID)
	stream, err := fleetagent.TelemetryDeliveryStreamID(agentID, session, fleetagent.PriorityP3)
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Unix(1_700_000_000, 0).UTC()
	ev := telemetry.TelemetryEvent{
		Class:   detection.ClassProcess,
		Process: &telemetry.ProcessObservation{Kind: "exec", PID: 101, EntityID: "proc-http-1", Comm: "http-test"},
	}
	env := telemetry.TelemetryEnvelope{
		SchemaVersion: telemetry.SchemaVersion,
		EventID:       "e1", EventType: ev.EventType(), EventClass: detection.ClassProcess,
		AgentID: agentID, AgentSessionID: shared.ID(session), AssetID: asset,
		BootID: "boot-1", StreamID: "sensor-stream-http", SensorID: "sensor-http", SensorVersion: "1",
		OccurredAt: observed.Add(-time.Millisecond), ObservedAt: observed, Sequence: 1,
		RedactionPolicyDigest: policyDigest,
		Event:                 ev,
	}
	payload, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	m := fleetagent.TelemetryBatchManifest{
		ProtocolVersion: fleetagent.TelemetryProtocolVersion, SchemaVersion: telemetry.SchemaVersion,
		BatchID: "batch-1", AgentID: agentID, HostID: agentID, AssetID: asset, StreamID: stream,
		Position:         fleetagent.StreamPosition{Priority: fleetagent.PriorityP3, Epoch: 1, Sequence: 1, Session: session, Boot: "boot-1"},
		PreviousSequence: 0,
		EventTimeMin:     observed, EventTimeMax: observed,
		ObservedCount: 1, KeptCount: 1, SamplingPolicyDigest: "test-policy-digest",
		Events: []fleetagent.EventRef{{ID: "e1", Digest: fleetagent.TelemetryEventDigest(payload, asset)}}, KeyID: keyID,
	}
	m.PayloadDigest = fleetagent.TelemetryPayloadDigest(m.Events)
	m.Signature = fleetagent.SignTelemetryManifest(priv, m)
	return telemetryingest.IngestRequest{Manifest: m, Events: []telemetryingest.EventPayload{{EventID: "e1", Class: detection.ClassProcess, Payload: payload, ObservedAt: observed}}}
}

func TestIngestTelemetryEndpointAccepts(t *testing.T) {
	h, agentSvc, priv, keyOf, policyDigest := setupFleetWithTelemetry(t, true)
	token, agentID := enrolAgent(t, h, agentSvc)
	req := signedRequest(t, agentID, keyOf(agentID), policyDigest, priv)
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
	h, agentSvc, priv, keyOf, policyDigest := setupFleetWithTelemetry(t, true)
	token, agentID := enrolAgent(t, h, agentSvc)
	keyID := keyOf(agentID)
	req := signedRequest(t, "someone-else", keyID, policyDigest, priv)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/telemetry", token, req, true)
	if w.Code != http.StatusForbidden {
		t.Fatalf("identity mismatch should be 403, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestIngestTelemetryEndpointHostMismatch403(t *testing.T) {
	h, agentSvc, priv, keyOf, policyDigest := setupFleetWithTelemetry(t, true)
	token, agentID := enrolAgent(t, h, agentSvc)
	req := signedRequest(t, agentID, keyOf(agentID), policyDigest, priv)
	req.Manifest.HostID = "someone-else"
	req.Manifest.Signature = fleetagent.SignTelemetryManifest(priv, req.Manifest)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/telemetry", token, req, true)
	if w.Code != http.StatusForbidden {
		t.Fatalf("host mismatch should be 403, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestIngestTelemetryEndpointNotEnabled404(t *testing.T) {
	h, agentSvc, priv, keyOf, policyDigest := setupFleetWithTelemetry(t, false)
	token, agentID := enrolAgent(t, h, agentSvc)
	req := signedRequest(t, agentID, keyOf(agentID), policyDigest, priv)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/telemetry", token, req, true)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unwired telemetry should be 404, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestIngestTelemetryEndpointRequiresAuth(t *testing.T) {
	h, _, _, _, _ := setupFleetWithTelemetry(t, true)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/telemetry", "", map[string]any{}, true)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no credential should be 401, got %d (%s)", w.Code, w.Body.String())
	}
}
