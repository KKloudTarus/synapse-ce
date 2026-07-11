package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/threatmodel"
)

// threatModelService is the engagement threat-model ingest/read use case. *threatmodeluc.Service
// satisfies it. nil on the Router ⇒ the routes are not registered.
type threatModelService interface {
	Ingest(ctx context.Context, principal string, tenantID, engagementID shared.ID, m threatmodel.Model) (threatmodel.ModelDelta, error)
	Get(ctx context.Context, engagementID shared.ID) (threatmodel.Model, bool, error)
}

// putThreatModel ingests (replaces) the engagement's architecture threat model. The body is the model
// (components / flows / trust-boundaries / assets); the use case bounds element counts, fail-closed-validates
// the DFD (referential integrity), persists it, and audits the action. The engagement is the path's – the
// tenant gate (withEngTenant) has already verified it belongs to the caller's tenant.
func (rt *Router) putThreatModel(w http.ResponseWriter, r *http.Request) {
	var m threatmodel.Model
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)) // 1 MiB edge cap; the use case also bounds element counts
	dec.DisallowUnknownFields()                                   // fail-closed: reject smuggled fields
	if err := dec.Decode(&m); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid threat-model json body"})
		return
	}
	delta, err := rt.threatModels.Ingest(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")), m)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	// surface what this architecture change altered – added/removed components+flows and, most
	// importantly, the data flows that newly cross (or no longer cross) a trust boundary = the attack-surface delta.
	writeJSON(w, http.StatusOK, map[string]any{"status": "ingested", "boundary_crossings": len(m.BoundaryCrossings()), "delta": delta})
}

// getThreatModel returns the engagement's current threat model (404 when none has been ingested).
func (rt *Router) getThreatModel(w http.ResponseWriter, r *http.Request) {
	m, ok, err := rt.threatModels.Get(r.Context(), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "no threat model ingested for this engagement"})
		return
	}
	writeJSON(w, http.StatusOK, m)
}
