package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/emulationrun"
)

// emulationRunner is the narrow HTTP slice for a governed adversary-emulation run: authorize + execute
// every catalogued technique against a target asset and compute its purple coverage.
// *emulationrun.Service satisfies it.
type emulationRunner interface {
	Run(ctx context.Context, engagementID, target shared.ID, actor string, allowLab bool) (emulationrun.Summary, error)
}

// SetEmulationRunner wires the governed emulation-run route. Left unset, the route is not registered
// (the sandbox / offensive governance the run needs is not available in this process posture).
func (rt *Router) SetEmulationRunner(s emulationRunner) {
	if s != nil {
		rt.emulation = s
	}
}

type emulationRunRequest struct {
	// Target is the asset id the run is attributed to; coverage is per-asset, so it is required.
	Target string `json:"target"`
	// AllowLabOnly opts in to techniques with no benign proof (they run only in a lab).
	AllowLabOnly bool `json:"allow_lab_only"`
}

// runEmulation authorizes and runs the emulation catalogue against the engagement's target asset, then
// returns the coverage summary. PermOperate + withEngTenant; the offensive gate additionally refuses
// unless the engagement's offensive rules of engagement are complete and the authorization window is open.
//
// The run is SYNCHRONOUS: the response is 200 with the computed coverage, not a 202 that would promise
// async processing this handler does not do. The catalogue is small (a handful of techniques), so the
// call is sub-second; if the catalogue grows toward ATT&CK scale, move execution to synapse-worker and
// return 202 + a run id with a status route, so the request thread is not held for the whole run.
func (rt *Router) runEmulation(w http.ResponseWriter, r *http.Request) {
	var req emulationRunRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	summary, err := rt.emulation.Run(r.Context(), shared.ID(r.PathValue("id")), shared.ID(req.Target), PrincipalFrom(r.Context()), req.AllowLabOnly)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, summary)
}
