package httpapi

import (
	"encoding/json"
	"fmt"
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

// runRuntimeVerification runs an approved DAST verification probe. When durable execution is wired the
// probe runs as a lease-executed worker job: the route enqueues it and returns 202 with the queued run,
// whose status the status route below polls. Without durable execution it falls back to running the probe
// synchronously in the request (dev / in-memory), returning 200 with the result.
func (rt *Router) runRuntimeVerification(w http.ResponseWriter, r *http.Request) {
	var body runtimeVerificationBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	engagementID, actionID := shared.ID(r.PathValue("id")), shared.ID(r.PathValue("aid"))
	probe := body.probe(r.PathValue("jid"))
	if rt.dastRun != nil {
		run, err := rt.dastRun.Submit(r.Context(), engagementID, actionID, PrincipalFrom(r.Context()), probe)
		if err != nil {
			writeError(w, rt.log, err)
			return
		}
		writeJSON(w, http.StatusAccepted, run)
		return
	}
	out, err := rt.dastWorkflow.Run(r.Context(), PrincipalFrom(r.Context()), engagementID, actionID, probe)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// getDASTRun returns the status of a durable DAST verification run. PermView + withEngTenant.
func (rt *Router) getDASTRun(w http.ResponseWriter, r *http.Request) {
	run, err := rt.dastRun.GetRun(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("rid")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if run.EngagementID != shared.ID(r.PathValue("id")) {
		writeError(w, rt.log, fmt.Errorf("%w: DAST run", shared.ErrNotFound))
		return
	}
	writeJSON(w, http.StatusOK, run)
}
