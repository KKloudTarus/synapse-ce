package httpapi

import (
	"context"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detectionprovenance"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// detectionProvenanceReader is the dedicated read side for immutable detection lifecycle facts.
// It intentionally does not expose ledger writes or persistence details to HTTP.
type detectionProvenanceReader interface {
	ListDetectionProvenance(ctx context.Context, engagementID shared.ID) ([]detectionprovenance.Current, error)
	DetectionProvenanceTransitions(ctx context.Context, engagementID, detectionID shared.ID) ([]detectionprovenance.Transition, error)
}

// SetDetectionProvenanceReader wires detection provenance read routes.
func (rt *Router) SetDetectionProvenanceReader(r detectionProvenanceReader) {
	if r != nil {
		rt.detectionProvenance = r
	}
}

func (rt *Router) listDetectionProvenance(w http.ResponseWriter, r *http.Request) {
	if rt.detectionProvenance == nil {
		writeJSON(w, http.StatusOK, map[string]any{"provenance": []detectionprovenance.Current{}})
		return
	}
	states, err := rt.detectionProvenance.ListDetectionProvenance(r.Context(), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"provenance": states})
}

func (rt *Router) listDetectionProvenanceTransitions(w http.ResponseWriter, r *http.Request) {
	if rt.detectionProvenance == nil {
		writeError(w, rt.log, shared.ErrNotFound)
		return
	}
	transitions, err := rt.detectionProvenance.DetectionProvenanceTransitions(
		r.Context(), shared.ID(r.PathValue("id")), shared.ID(r.PathValue("did")),
	)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"transitions": transitions})
}
