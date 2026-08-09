package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastrunner"
)

type runtimeVerificationBody struct {
	URL                  string `json:"url"`
	Method               string `json:"method"`
	ExpectedStatus       int    `json:"expected_status"`
	ExpectedBodyContains string `json:"expected_body_contains"`
	ScoreIfConfirmed     int    `json:"score_if_confirmed"`
	ScoreIfRefuted       int    `json:"score_if_refuted"`
	Version              int    `json:"version"`
	Rationale            string `json:"rationale"`
}

func (b runtimeVerificationBody) probe(jid string) dastrunner.Probe {
	return dastrunner.Probe{
		JudgmentID:           shared.ID(jid),
		URL:                  b.URL,
		Method:               b.Method,
		ExpectedStatus:       b.ExpectedStatus,
		ExpectedBodyContains: b.ExpectedBodyContains,
		ScoreIfConfirmed:     b.ScoreIfConfirmed,
		ScoreIfRefuted:       b.ScoreIfRefuted,
		ExpectedVersion:      b.Version,
		Rationale:            b.Rationale,
	}
}

func (rt *Router) proposeRuntimeVerification(w http.ResponseWriter, r *http.Request) {
	var body runtimeVerificationBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	out, err := rt.dastWorkflow.Propose(r.Context(), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")), body.probe(r.PathValue("jid")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusAccepted, out)
}

func (rt *Router) decideRuntimeVerification(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Approve bool   `json:"approve"`
		Reason  string `json:"reason"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	out, err := rt.dastWorkflow.Decide(r.Context(), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")), shared.ID(r.PathValue("aid")), body.Approve, body.Reason)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (rt *Router) runRuntimeVerification(w http.ResponseWriter, r *http.Request) {
	var body runtimeVerificationBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	out, err := rt.dastWorkflow.Run(r.Context(), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")), shared.ID(r.PathValue("aid")), body.probe(r.PathValue("jid")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
