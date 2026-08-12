package httpapi

import (
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func (rt *Router) getAITriageObservability(w http.ResponseWriter, r *http.Request) {
	dashboard, err := rt.sca.AITriageObservability(r.Context(), shared.ID(TenantFrom(r.Context())))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, dashboard)
}
