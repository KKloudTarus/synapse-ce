package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetdesired"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	desireduc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/desired"
)

// desiredCapabilityService is the #633 desired-vs-observed surface: declare the capabilities an asset
// SHOULD have, read them, clear them, and list the gaps against the observed agent fleet. desired.Service
// satisfies it. Actor + tenant + asset are server-side (principal / fleet tenant / path id), never body.
type desiredCapabilityService interface {
	SetDesiredCapabilities(ctx context.Context, in desireduc.SetInput) (*fleetdesired.State, error)
	Get(ctx context.Context, tenantID, assetID shared.ID) (*fleetdesired.State, error)
	ClearDesiredCapabilities(ctx context.Context, in desireduc.ClearInput) error
	Gaps(ctx context.Context, tenantID shared.ID) ([]desireduc.ReconciliationRow, error)
}

// SetDesiredCapabilities wires the desired-vs-observed surface (nil ⇒ the routes are not registered).
func (rt *Router) SetDesiredCapabilities(s desiredCapabilityService) { rt.desiredCapabilities = s }

type setDesiredRequest struct {
	Capabilities []string `json:"capabilities"`
}

const desiredBodyLimit = 16 << 10

func (rt *Router) setDesiredCapabilities(w http.ResponseWriter, r *http.Request) {
	var req setDesiredRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, desiredBodyLimit)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	state, err := rt.desiredCapabilities.SetDesiredCapabilities(incidentTenantContext(r), desireduc.SetInput{
		TenantID:     fleetTenant(r.Context()),
		AssetID:      shared.ID(r.PathValue("id")),
		Capabilities: req.Capabilities,
		Actor:        shared.ID(PrincipalFrom(r.Context())),
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (rt *Router) getDesiredCapabilities(w http.ResponseWriter, r *http.Request) {
	state, err := rt.desiredCapabilities.Get(incidentTenantContext(r), fleetTenant(r.Context()), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (rt *Router) clearDesiredCapabilities(w http.ResponseWriter, r *http.Request) {
	err := rt.desiredCapabilities.ClearDesiredCapabilities(incidentTenantContext(r), desireduc.ClearInput{
		TenantID: fleetTenant(r.Context()),
		AssetID:  shared.ID(r.PathValue("id")),
		Actor:    shared.ID(PrincipalFrom(r.Context())),
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (rt *Router) listDesiredGaps(w http.ResponseWriter, r *http.Request) {
	rows, err := rt.desiredCapabilities.Gaps(incidentTenantContext(r), fleetTenant(r.Context()))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"gaps": rows})
}
