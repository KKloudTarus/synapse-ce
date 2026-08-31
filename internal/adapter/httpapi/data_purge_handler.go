package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// dataPurger performs an on-demand governed deletion of an engagement's detection projection (#635,
// right-to-erasure). detectledger.Service satisfies it via Purge. The delete is legal-hold-checked,
// audited with the actor+reason, and never touches the permanent evidence chain — only the queryable
// projection. Actor + tenant are server-side; the caller supplies only a reason.
type dataPurger interface {
	Purge(ctx context.Context, engagementID shared.ID, actor, reason string) (int, error)
}

// SetDataPurge wires the on-demand data-deletion surface (nil ⇒ the route is not registered).
func (rt *Router) SetDataPurge(p dataPurger) { rt.dataPurge = p }

type purgeDataRequest struct {
	Reason string `json:"reason"`
}

// purgeEngagementData deletes ALL of an engagement's detection projection rows on demand. Destructive
// and irreversible for the projection (the chain is preserved), so it demands an explicit reason for
// accountability; a held engagement refuses (fail-closed in the usecase).
func (rt *Router) purgeEngagementData(w http.ResponseWriter, r *http.Request) {
	var req purgeDataRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, legalHoldBodyLimit)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	purged, err := rt.dataPurge.Purge(incidentTenantContext(r), shared.ID(r.PathValue("id")), PrincipalFrom(r.Context()), req.Reason)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"purged": purged})
}
