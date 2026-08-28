package httpapi

import (
	"context"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// detectionReader is the narrow read side the HTTP layer needs for the detection ledger (#423): the
// engagement's chained detections and their incident rollup. *detectledger.Service satisfies it. Reads
// are tenant-gated by withEngTenant + the store's RLS, so a cross-tenant read returns nothing.
type detectionReader interface {
	ListDetections(ctx context.Context, engagementID shared.ID) ([]detection.Record, error)
	Incidents(ctx context.Context, engagementID shared.ID) ([]detection.Incident, error)
}

// SetDetectionReader wires the detection read routes (#423). Left unset, the routes report an empty
// ledger rather than 500 — the feature is simply not enabled.
func (rt *Router) SetDetectionReader(r detectionReader) {
	if r != nil {
		rt.detections = r
	}
}

// listDetections returns the engagement's chained detections, or — with ?view=incidents — the incident
// rollup over them (the individual detections remain the ledger underneath). PermView + withEngTenant;
// a cross-tenant engagement is already a 404 before this runs. A6 adds a second, field-level authz layer
// to the evidence-bearing records view and requires a query-audit entry before either read executes.
func (rt *Router) listDetections(w http.ResponseWriter, r *http.Request) {
	engID := shared.ID(r.PathValue("id"))
	if r.URL.Query().Get("view") == "incidents" {
		if err := rt.auditDetectionQuery(r.Context(), engID, "incidents", detectionFieldScopeSummary); err != nil {
			writeError(w, rt.log, err)
			return
		}
		if rt.detections == nil {
			writeJSON(w, http.StatusOK, map[string]any{"incidents": []detection.Incident{}, "field_scope": detectionFieldScopeSummary})
			return
		}
		inc, err := rt.detections.Incidents(r.Context(), engID)
		if err != nil {
			writeError(w, rt.log, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"incidents": inc, "field_scope": detectionFieldScopeSummary})
		return
	}

	scope, err := detectionFieldScopeFor(r.Context())
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if err := rt.auditDetectionQuery(r.Context(), engID, "records", scope); err != nil {
		writeError(w, rt.log, err)
		return
	}
	if rt.detections == nil {
		writeJSON(w, http.StatusOK, map[string]any{"detections": []detection.Record{}, "field_scope": scope})
		return
	}
	recs, err := rt.detections.ListDetections(r.Context(), engID)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"detections": projectDetectionRecords(recs, scope), "field_scope": scope})
}
