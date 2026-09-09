package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	responseobserveruc "github.com/KKloudTarus/synapse-ce/internal/usecase/fleet/responseobserver"
)

type responseObserverAdmin interface {
	Assign(context.Context, responseobserveruc.AssignInput) (fleetagent.ResponseObserverBinding, error)
}

func (rt *Router) SetResponseObserverAdmin(service responseObserverAdmin) {
	rt.responseObservers = service
}

func (rt *Router) assignResponseObserver(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ExpiresAt       time.Time `json:"expires_at"`
		ExpectedVersion int       `json:"expected_version"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, fleetBodyCap)).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid response-observer assignment body"})
		return
	}
	binding, err := rt.responseObservers.Assign(r.Context(), responseobserveruc.AssignInput{
		TenantID: requestTenant(r), AgentID: shared.ID(r.PathValue("agentID")), AssetID: shared.ID(r.PathValue("id")),
		Actor: PrincipalFrom(r.Context()), ExpiresAt: request.ExpiresAt, ExpectedVersion: request.ExpectedVersion,
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	status := http.StatusOK
	if binding.Version == 1 {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{
		"agent_id": binding.AgentID, "asset_id": binding.AssetID, "assigned_by": binding.AssignedBy,
		"assigned_at": binding.AssignedAt, "expires_at": binding.ExpiresAt, "version": binding.Version,
	})
}
