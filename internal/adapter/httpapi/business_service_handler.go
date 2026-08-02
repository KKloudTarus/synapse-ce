package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	assetuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assetuc"
)

type createBusinessServiceRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Criticality asset.Criticality `json:"criticality"`
	Lifecycle   asset.Lifecycle   `json:"lifecycle"`
}

type updateBusinessServiceRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Criticality asset.Criticality `json:"criticality"`
	Lifecycle   asset.Lifecycle   `json:"lifecycle"`
}

type businessServiceResponse struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Criticality asset.Criticality `json:"criticality"`
	Lifecycle   asset.Lifecycle   `json:"lifecycle"`
}

func businessServiceDTO(s asset.BusinessService) businessServiceResponse {
	return businessServiceResponse{ID: s.ID.String(), Name: s.Name, Description: s.Description, Criticality: s.Criticality, Lifecycle: s.Lifecycle}
}

func (rt *Router) createBusinessService(w http.ResponseWriter, r *http.Request) {
	var req createBusinessServiceRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	s, err := rt.businessServices.CreateBusinessService(r.Context(), assetuc.CreateBusinessServiceInput{TenantID: shared.ID(TenantFrom(r.Context())), Actor: PrincipalFrom(r.Context()), Name: req.Name, Description: req.Description, Criticality: req.Criticality, Lifecycle: req.Lifecycle})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, businessServiceDTO(s))
}

func (rt *Router) listBusinessServices(w http.ResponseWriter, r *http.Request) {
	services, err := rt.businessServices.ListBusinessServices(r.Context())
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]businessServiceResponse, len(services))
	for i, s := range services {
		out[i] = businessServiceDTO(s)
	}
	writeJSON(w, http.StatusOK, out)
}

func (rt *Router) getBusinessService(w http.ResponseWriter, r *http.Request) {
	s, err := rt.businessServices.GetBusinessService(r.Context(), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, businessServiceDTO(s))
}

func (rt *Router) updateBusinessService(w http.ResponseWriter, r *http.Request) {
	var req updateBusinessServiceRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	s, err := rt.businessServices.UpdateBusinessService(r.Context(), shared.ID(r.PathValue("id")), assetuc.UpdateBusinessServiceInput{Actor: PrincipalFrom(r.Context()), Name: req.Name, Description: req.Description, Criticality: req.Criticality, Lifecycle: req.Lifecycle})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, businessServiceDTO(s))
}

func (rt *Router) deleteBusinessService(w http.ResponseWriter, r *http.Request) {
	if err := rt.businessServices.DeleteBusinessService(r.Context(), shared.ID(r.PathValue("id"))); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
