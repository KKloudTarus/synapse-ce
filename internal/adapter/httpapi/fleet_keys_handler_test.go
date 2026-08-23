package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	userdom "github.com/KKloudTarus/synapse-ce/internal/domain/user"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/platform/worksign"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/keyregistry"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetagentuc"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleetwork"
)

// enrolTenant is the tenant enrolAgent's minted token binds the agent to (see MintEnrolToken(..,"default",..)).
const enrolTenant = shared.ID("default")

func setupFleetWithKeys(t *testing.T, wire bool) (*Router, http.Handler, *fleetagentuc.Service) {
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
	keyRegSvc, err := keyregistry.NewService(memory.NewAgentSigningKeyStore(), ftAudit{}, ftClock{})
	if err != nil {
		t.Fatal(err)
	}
	rt := &Router{log: discardLog()}
	rt.SetFleet(agentSvc, workSvc, func() time.Time { return time.Now().UTC() }, "")
	if wire {
		rt.SetFleetKeyRegistration(keyRegSvc)
		rt.SetFleetKeyAdmin(keyRegSvc)
	}
	return rt, rt.fleet.handler(), agentSvc
}

// signedKeyBody builds a valid registration body for agentID: a fresh keypair, a proof-of-possession over
// the key's binding message, and the returned private key so a test can also craft a bad proof.
func signedKeyBody(t *testing.T, agentID shared.ID) (map[string]any, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	nb, na := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	key, err := fleetagent.NewSigningKey(agentID, fleetagent.PurposeDetectionBatch, pub, nb, na)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"public_key": base64.StdEncoding.EncodeToString(pub),
		"purpose":    string(fleetagent.PurposeDetectionBatch),
		"not_before": nb.UTC().Format(time.RFC3339),
		"not_after":  na.UTC().Format(time.RFC3339),
		"proof":      fleetagent.ProveKeyPossession(priv, key),
	}, pub
}

func operatorReq(method, path string, tenant shared.ID) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	ctx := context.WithValue(req.Context(), principalKey, Principal{ID: "operator", Name: "operator", Role: "admin", TenantID: string(tenant)})
	return req.WithContext(shared.WithTenant(ctx, tenant))
}

func TestRegisterKeyEndpointAndOperatorLifecycle(t *testing.T) {
	rt, h, agentSvc := setupFleetWithKeys(t, true)
	token, agentID := enrolAgent(t, h, agentSvc)

	// Agent-plane registration with a valid proof.
	body, _ := signedKeyBody(t, agentID)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/keys", token, body, true)
	if w.Code != http.StatusCreated {
		t.Fatalf("register should be 201, got %d (%s)", w.Code, w.Body.String())
	}
	var reg struct {
		KeyID string `json:"key_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reg); err != nil || reg.KeyID == "" {
		t.Fatalf("register response: %+v err=%v (%s)", reg, err, w.Body.String())
	}

	// Operator lists the agent's keys (human RBAC plane).
	listReq := operatorReq(http.MethodGet, "/api/v1/agents/"+agentID.String()+"/keys", enrolTenant)
	listReq.SetPathValue("id", agentID.String())
	listRec := httptest.NewRecorder()
	rt.authz(userdom.PermView, rt.listAgentKeys)(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("operator list should be 200, got %d (%s)", listRec.Code, listRec.Body.String())
	}
	var listed struct {
		Keys []struct {
			KeyID   string `json:"key_id"`
			Revoked bool   `json:"revoked"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listed); err != nil || len(listed.Keys) != 1 || listed.Keys[0].KeyID != reg.KeyID {
		t.Fatalf("operator list: %+v err=%v (%s)", listed, err, listRec.Body.String())
	}

	// Operator revokes it.
	revReq := operatorReq(http.MethodPost, "/api/v1/agents/"+agentID.String()+"/keys/"+reg.KeyID+"/revoke", enrolTenant)
	revReq.SetPathValue("id", agentID.String())
	revReq.SetPathValue("keyID", reg.KeyID)
	revRec := httptest.NewRecorder()
	rt.authz(userdom.PermAdminister, rt.revokeAgentKey)(revRec, revReq)
	if revRec.Code != http.StatusOK {
		t.Fatalf("operator revoke should be 200, got %d (%s)", revRec.Code, revRec.Body.String())
	}

	// The key now lists as revoked.
	list2 := operatorReq(http.MethodGet, "/api/v1/agents/"+agentID.String()+"/keys", enrolTenant)
	list2.SetPathValue("id", agentID.String())
	rec2 := httptest.NewRecorder()
	rt.listAgentKeys(rec2, list2)
	if err := json.Unmarshal(rec2.Body.Bytes(), &listed); err != nil || len(listed.Keys) != 1 || !listed.Keys[0].Revoked {
		t.Fatalf("key must list as revoked after revoke: %+v err=%v", listed, err)
	}
}

func TestRegisterKeyEndpointBadProof403(t *testing.T) {
	_, h, agentSvc := setupFleetWithKeys(t, true)
	token, agentID := enrolAgent(t, h, agentSvc)
	body, _ := signedKeyBody(t, agentID)
	body["proof"] = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)) // zero signature: invalid
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/keys", token, body, true)
	if w.Code != http.StatusForbidden {
		t.Fatalf("bad proof should be 403, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestRegisterKeyEndpointNotEnabled404(t *testing.T) {
	_, h, agentSvc := setupFleetWithKeys(t, false)
	token, agentID := enrolAgent(t, h, agentSvc)
	body, _ := signedKeyBody(t, agentID)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/keys", token, body, true)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unwired key registration should be 404, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestRegisterKeyEndpointRequiresAuth(t *testing.T) {
	_, h, _ := setupFleetWithKeys(t, true)
	w := fleetCall(h, http.MethodPost, "/api/v1/fleet/keys", "", map[string]any{}, true)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no credential should be 401, got %d (%s)", w.Code, w.Body.String())
	}
}
