package httpapi

import (
	"context"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/privacyexport"
)

// privacyExporter assembles a data-subject / DPO export for one engagement (#635). privacyexport.Service
// satisfies it. The actor is the authenticated principal; the export is an audited governance read.
type privacyExporter interface {
	Export(ctx context.Context, actor string, engagementID shared.ID) (privacyexport.Bundle, error)
}

// SetPrivacyExport wires the data-export surface (nil ⇒ the route is not registered).
func (rt *Router) SetPrivacyExport(e privacyExporter) { rt.privacyExport = e }

// exportEngagementData returns the governance data-export bundle for one engagement (detections + active
// legal holds). Read-only + audited; no request body.
func (rt *Router) exportEngagementData(w http.ResponseWriter, r *http.Request) {
	bundle, err := rt.privacyExport.Export(incidentTenantContext(r), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, bundle)
}
