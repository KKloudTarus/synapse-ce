package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/legalhold"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// legalHoldService is the #635 legal-hold surface: place/release a hold on an engagement's data and list
// the active holds. legalholduc.Service satisfies it. Actor + tenant are server-side; a held engagement's
// data is exempt from retention expiry.
type legalHoldService interface {
	Place(ctx context.Context, actor string, engagementID shared.ID, reason string) (legalhold.Hold, error)
	Release(ctx context.Context, actor string, engagementID shared.ID) error
	ListActive(ctx context.Context) ([]legalhold.Hold, error)
}

// SetLegalHolds wires the legal-hold surface (nil ⇒ the routes are not registered).
func (rt *Router) SetLegalHolds(s legalHoldService) { rt.legalHolds = s }

const legalHoldBodyLimit = 8 << 10

type placeLegalHoldRequest struct {
	Reason string `json:"reason"`
}

func (rt *Router) placeLegalHold(w http.ResponseWriter, r *http.Request) {
	var req placeLegalHoldRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, legalHoldBodyLimit)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	hold, err := rt.legalHolds.Place(incidentTenantContext(r), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id")), req.Reason)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, hold)
}

func (rt *Router) releaseLegalHold(w http.ResponseWriter, r *http.Request) {
	if err := rt.legalHolds.Release(incidentTenantContext(r), PrincipalFrom(r.Context()), shared.ID(r.PathValue("id"))); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (rt *Router) listLegalHolds(w http.ResponseWriter, r *http.Request) {
	holds, err := rt.legalHolds.ListActive(incidentTenantContext(r))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"holds": holds})
}
