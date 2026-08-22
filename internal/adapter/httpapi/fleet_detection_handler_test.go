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
	detectledger "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/detectledger"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetagentuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetwork"
)

// fakeDetChain is a minimal EvidenceChain for the handler test: it seals a deterministic id per
// (engagement, key) and never reports a broken chain. The real bridge is exercised in the evidence and
// detectledger packages; here we only need the HTTP path to reach the ledger.
type fakeDetChain struct{}

func (fakeDetChain) SealOnce(_ context.Context, _ shared.ID, _, key string, _ []byte, _ string) (shared.ID, error) {
	return shared.ID("ev-" + key), nil
}
func (fakeDetChain) Verify(_ context.Context, _ shared.ID) error { return nil }

type detKeyResolver struct{ key fleetagent.AgentSigningKey }

func (r *detKeyResolver) ResolveSigningKey(_ context.Context, agentID shared.ID, keyID string) (fleetagent.AgentSigningKey, error) {
	if agentID == r.key.AgentID && keyID == r.key.KeyID {
		return r.key, nil
	}
	return fleetagent.AgentSigningKey{}, shared.ErrNotFound
}

func setupFleetWithDetections(t *testing.T, wire bool) (http.Handler, *fleetagentuc.Service, ed25519.PrivateKey, func(agentID shared.ID) string) {
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
	resolver := &detKeyResolver{}
	keyOf := func(agentID shared.ID) string {
		key, err := fleetagent.NewSigningKey(agentID, fleetagent.PurposeDetectionBatch, pub, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		resolver.key = key
		return key.KeyID
	}
	detSvc, err := detectledger.NewService(memory.NewDetectionRecordStore(), fakeDetChain{}, resolver, ftAudit{}, ftClock{}, &ftIDs{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: discardLog()}
	rt.SetFleet(agentSvc, workSvc, func() time.Time { return time.Now().UTC() }, "")
	if wire {
		rt.SetFleetDetectionIngest(detSvc)
	}
	return rt.fleet.handler(), agentSvc, priv, keyOf
}

func mkTestDetection(t *testing.T, agentID shared.ID) detection.Detection {
	t.Helper()
	r, ok := detection.Lookup("det.process_enumeration")
	if !ok {
		t.Fatal("expected det.process_enumeration rule")
	}
	ev := detection.Event{Class: detection.ClassProcess, At: time.Unix(1, 0), Host: "h",
		Process: &detection.ProcessEvent{PID: 1, Comm: "ps", Path: "/usr/bin/ps"}}
	d, err := detection.NewDetection(r, "host-1", agentID, []detection.Event{ev}, time.Unix(500, 0))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func signedDetectionBody(t *testing.T, agentID shared.ID, keyID string, priv ed25519.PrivateKey) map[string]any {
	t.Helper()
	det := mkTestDetection(t, agentID)
	asset := shared.ID("asset-1")
	payload, err := json.Marshal(det)
	if err != nil {
		t.Fatal(err)
	}
	batch := fleetagent.AgentBatch{
		AgentID: agentID, EngagementID: "eng-1", Sequence: 1, KeyID: keyID,
		Detections: []fleetagent.DetectionRef{{ID: "d1", ContentSHA256: fleetagent.DetectionContentHash(payload, asset)}},
	}
	batch.Signature = fleetagent.SignBatch(priv, batch)
	return map[string]any{
		"batch": batch,
		"items": []detectledger.IngestItem{{ID: "d1", Detection: det, AssetID: asset}},
	}
}

func TestIngestDetectionsEndpointAccepts(t *testing.T) {
	h, agentSvc, priv, keyOf := setupFleetWithDetections(t, true)
	token, agentID := enrolAgent(t, h, agentSvc)
	body := signedDetectionBody(t, agentID, keyOf(agentID), priv)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/detections", token, body, true)
	if w.Code != http.StatusOK {
		t.Fatalf("ingest should be 200, got %d (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Sealed  int `json:"sealed"`
		Skipped int `json:"skipped"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Sealed != 1 {
		t.Fatalf("accept response: %+v err=%v (%s)", resp, err, w.Body.String())
	}
}

func TestIngestDetectionsEndpointIdentityMismatch403(t *testing.T) {
	h, agentSvc, priv, keyOf := setupFleetWithDetections(t, true)
	token, agentID := enrolAgent(t, h, agentSvc)
	keyID := keyOf(agentID)
	// A batch claiming a DIFFERENT agent than the authenticated credential must be forbidden (A0.1).
	body := signedDetectionBody(t, "someone-else", keyID, priv)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/detections", token, body, true)
	if w.Code != http.StatusForbidden {
		t.Fatalf("identity mismatch should be 403, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestIngestDetectionsEndpointNotEnabled404(t *testing.T) {
	h, agentSvc, priv, keyOf := setupFleetWithDetections(t, false)
	token, agentID := enrolAgent(t, h, agentSvc)
	body := signedDetectionBody(t, agentID, keyOf(agentID), priv)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/detections", token, body, true)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unwired detection ingest should be 404, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestIngestDetectionsEndpointRequiresAuth(t *testing.T) {
	h, _, _, _ := setupFleetWithDetections(t, true)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/detections", "", map[string]any{}, true)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no credential should be 401, got %d (%s)", w.Code, w.Body.String())
	}
}
