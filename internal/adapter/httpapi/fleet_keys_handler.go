package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/keyregistry"
)

// fleetKeyRegistration is the narrow agent-plane signing-key registration surface (#607, A0.2). The
// keyregistry.Service satisfies it; authAgentID is passed from the credential so a key is always bound to
// the authenticated agent, never a wire field.
type fleetKeyRegistration interface {
	Register(ctx context.Context, authAgentID shared.ID, req keyregistry.RegisterRequest) (fleetagent.AgentSigningKey, error)
}

// fleetKeyAdmin is the operator-facing (human, RBAC-gated) view of signing-key management: list an agent's
// keys and revoke one. Tenant-scoped from the operator's authenticated context.
type fleetKeyAdmin interface {
	List(ctx context.Context, agentID shared.ID) ([]fleetagent.AgentSigningKey, error)
	Revoke(ctx context.Context, agentID shared.ID, keyID, actor string) error
}

// registerKey is the agent-plane endpoint (POST /api/v1/fleet/keys): an agent posts its Ed25519 signing
// public key + a proof-of-possession bound to its canonical AgentID; the service verifies the proof BEFORE
// registering (fail-closed). The agent id comes from the authenticated credential, never the body — a proof
// made for another agent will not verify.
func (f *fleetRouter) registerKey(w http.ResponseWriter, r *http.Request) {
	if f.keyReg == nil {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "key registration not enabled"})
		return
	}
	agent, ok := agentFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthenticated"})
		return
	}
	var req struct {
		PublicKey string    `json:"public_key"` // base64 Ed25519
		Purpose   string    `json:"purpose"`
		NotBefore time.Time `json:"not_before"`
		NotAfter  time.Time `json:"not_after"`
		Proof     string    `json:"proof"` // base64 PoP signature over the key binding message
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, fleetBodyCap)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid key registration body"})
		return
	}
	key, err := f.keyReg.Register(r.Context(), agent.ID, keyregistry.RegisterRequest{
		PublicKeyB64: req.PublicKey, Purpose: req.Purpose, NotBefore: req.NotBefore, NotAfter: req.NotAfter, Proof: req.Proof,
	})
	if err != nil {
		writeError(w, f.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"key_id":     key.KeyID,
		"agent_id":   key.AgentID.String(),
		"purpose":    string(key.Purpose),
		"not_before": key.NotBefore.UTC().Format(time.RFC3339),
		"not_after":  key.NotAfter.UTC().Format(time.RFC3339),
	})
}

// listAgentKeys is the operator endpoint (GET /api/v1/agents/{id}/keys): list an agent's signing keys.
func (rt *Router) listAgentKeys(w http.ResponseWriter, r *http.Request) {
	agentID := shared.ID(r.PathValue("id"))
	keys, err := rt.fleetKeys.List(r.Context(), agentID)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]any{
			"key_id": k.KeyID, "purpose": string(k.Purpose), "algorithm": string(k.Algorithm),
			"not_before": k.NotBefore.UTC().Format(time.RFC3339), "not_after": k.NotAfter.UTC().Format(time.RFC3339),
			"revoked": !k.RevokedAt.IsZero(), "replaced_by": k.ReplacedBy,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent_id": agentID.String(), "keys": out})
}

// revokeAgentKey is the operator endpoint (POST /api/v1/agents/{id}/keys/{keyID}/revoke): revoke one key.
func (rt *Router) revokeAgentKey(w http.ResponseWriter, r *http.Request) {
	agentID := shared.ID(r.PathValue("id"))
	keyID := r.PathValue("keyID")
	if err := rt.fleetKeys.Revoke(r.Context(), agentID, keyID, PrincipalFrom(r.Context())); err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"agent_id": agentID.String(), "key_id": keyID, "state": "revoked"})
}
