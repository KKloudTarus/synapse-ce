package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/purplecoverage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	purpleteamuc "github.com/KKloudTarus/synapse-ce/internal/usecase/purpleteam"
)

// purpleCoverageReader is the narrow read side the HTTP layer needs for purple-team coverage (#426): an
// engagement's coverage across runs (the trend) and the work items (one per gap) derived from it.
// *purplecoverageuc.Service satisfies it. Reads are tenant-gated by withEngTenant + the store's RLS, so a
// cross-tenant read returns nothing.
type purpleCoverageReader interface {
	Trend(ctx context.Context, engagementID shared.ID) ([]purplecoverage.Coverage, error)
	WorkItems(ctx context.Context, engagementID, runID shared.ID) ([]purplecoverage.WorkItem, error)
}

// SetPurpleCoverageReader wires the purple-coverage read route (#426). Left unset, the route reports empty
// coverage rather than 500 — the feature is simply not enabled.
func (rt *Router) SetPurpleCoverageReader(r purpleCoverageReader) {
	if r != nil {
		rt.purpleCoverage = r
	}
}

// purpleTeamRunner runs a governed adversary-emulation run and produces the purple-team coverage the read
// side above then serves. *purpleteamuc.Service satisfies it. Left unset, the run route is not registered.
type purpleTeamRunner interface {
	RunEmulation(ctx context.Context, tenantID, engagementID, target shared.ID, actor string) (purpleteamuc.Result, error)
}

// SetPurpleTeam wires the adversary-emulation run route (#426 producer). It requires the offensive policy
// and the emulation + coverage stores; left unset, the run route is not registered.
func (rt *Router) SetPurpleTeam(r purpleTeamRunner) { rt.purpleTeam = r }

type runEmulationRequest struct {
	Target string `json:"target"` // the asset id the techniques run against and coverage attributes to
}

// runEmulation runs the governed adversary-emulation catalogue for an engagement and returns the run plus
// the purple coverage it produced. PermOperate + tenant-scoped: the run is admitted, per technique, through
// the engagement's rules of engagement, so a technique an incomplete RoE refuses is recorded as not
// executed (verdict unknown), never run.
func (rt *Router) runEmulation(w http.ResponseWriter, r *http.Request) {
	var req runEmulationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	result, err := rt.purpleTeam.RunEmulation(r.Context(), shared.ID(TenantFrom(r.Context())),
		shared.ID(r.PathValue("id")), shared.ID(req.Target), PrincipalFrom(r.Context()))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// listPurpleCoverage returns the engagement's coverage across runs (the trend), or — with ?run=<id> — the
// work items (one per gap) for a single run. PermView + withEngTenant; a cross-tenant engagement is
// already a 404 before this runs.
func (rt *Router) listPurpleCoverage(w http.ResponseWriter, r *http.Request) {
	engID := shared.ID(r.PathValue("id"))
	if rt.purpleCoverage == nil {
		// Not wired: an empty, honest answer (not a 500), consistent with the read being optional.
		writeJSON(w, http.StatusOK, map[string]any{"coverage": []purplecoverage.Coverage{}})
		return
	}
	if runID := r.URL.Query().Get("run"); runID != "" {
		// The run is bound to the path engagement inside WorkItems, so a run id from another engagement in
		// the same tenant resolves to no items rather than leaking that engagement's gaps.
		items, err := rt.purpleCoverage.WorkItems(r.Context(), engID, shared.ID(runID))
		if err != nil {
			writeError(w, rt.log, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"work_items": items})
		return
	}
	cov, err := rt.purpleCoverage.Trend(r.Context(), engID)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"coverage": cov})
}
