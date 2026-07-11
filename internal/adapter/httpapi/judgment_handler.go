package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	dastverifieruc "github.com/KKloudTarus/synapse-ce/internal/usecase/dastverifier"
)

// listJudgments returns the engagement's AI judgments (read; PermView + tenant-gated via
// withEngTenant). The typed Claim renders as fields – no LLM prose.
func (rt *Router) listJudgments(w http.ResponseWriter, r *http.Request) {
	js, err := rt.judgments.List(r.Context(), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"judgments": js})
}

// verifyJudgment applies a DISTINCT verifier's verdict to a GATED judgment (PermReview = sign-off
// with separation of duties; machine/agent roles are never granted PermReview). The use case seals
// the verdict before moving the score (fail-closed); self-confirm / ungated / bad score → 400,
// version mismatch → 409.
func (rt *Router) verifyJudgment(w http.ResponseWriter, r *http.Request) {
	engID, jid := r.PathValue("id"), r.PathValue("jid")
	if engID == "" || jid == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id and judgment id are required"})
		return
	}
	var body struct {
		Score     int    `json:"score"`
		Rationale string `json:"rationale"`
		Version   int    `json:"version"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	updated, err := rt.judgments.Verify(r.Context(), PrincipalFrom(r.Context()), shared.ID(engID), shared.ID(jid), body.Score, body.Rationale, body.Version)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// acceptJudgment confirms an UNGATED judgment by human acceptance (PermReview; the acceptor must be
// a non-proposer – enforced in the domain). Optimistic concurrency via the client-supplied version.
func (rt *Router) acceptJudgment(w http.ResponseWriter, r *http.Request) {
	engID, jid := r.PathValue("id"), r.PathValue("jid")
	if engID == "" || jid == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id and judgment id are required"})
		return
	}
	var body struct {
		Version int `json:"version"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	updated, err := rt.judgments.Accept(r.Context(), PrincipalFrom(r.Context()), shared.ID(engID), shared.ID(jid), body.Version)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// applyRuntimeVerification ingests an approved runtime-verifier result for a gated AppSec/SAST
// judgment. This endpoint is intentionally not a DAST runner: it accepts closed proof metadata and
// lets dastverifier -> analysis.Verify enforce distinct verifier, sealed verdict, and score movement.
func (rt *Router) applyRuntimeVerification(w http.ResponseWriter, r *http.Request) {
	engID, jid := r.PathValue("id"), r.PathValue("jid")
	if engID == "" || jid == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "engagement id and judgment id are required"})
		return
	}
	var body struct {
		Score      int    `json:"score"`
		ProofClass string `json:"proof_class"`
		Rationale  string `json:"rationale"`
		Version    int    `json:"version"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	updated, err := rt.dastVerifier.Apply(r.Context(), shared.ID(engID), dastverifieruc.Result{
		JudgmentID:      shared.ID(jid),
		Verifier:        PrincipalFrom(r.Context()),
		Score:           body.Score,
		ProofClass:      dastverifieruc.ProofClass(body.ProofClass),
		Rationale:       body.Rationale,
		ExpectedVersion: body.Version,
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}
