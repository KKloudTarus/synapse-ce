package httpapi

import (
	"encoding/json"
	"fmt"

	"io"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/cspm"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const cspmBodyCap = 64 << 10

func (rt *Router) SetCSPM(service *cspm.Service) { rt.cspm = service }

type cspmRunRequest struct {
	Targets []ports.CloudScope `json:"targets"`
}

func (rt *Router) runCSPM(w http.ResponseWriter, r *http.Request) {
	engagementID := shared.ID(r.PathValue("id"))
	var request cspmRunRequest
	r.Body = http.MaxBytesReader(w, r.Body, cspmBodyCap)
	decoder := json.NewDecoder(io.LimitReader(r.Body, cspmBodyCap))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "request body must contain one JSON object"})
		return
	}
	tenantID := TenantFrom(r.Context())
	actor := PrincipalFrom(r.Context())
	for i := range request.Targets {
		request.Targets[i].EngagementID = engagementID
	}
	result, err := rt.cspm.Submit(r.Context(), cspm.RunInput{TenantID: shared.ID(tenantID), EngagementID: engagementID, Actor: actor, Scopes: request.Targets})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusAccepted, result)
}

func (rt *Router) getCSPMRun(w http.ResponseWriter, r *http.Request) {
	run, err := rt.cspm.GetRun(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("rid")))
	if err == nil && run.EngagementID != shared.ID(r.PathValue("id")) {
		err = fmt.Errorf("%w: CSPM run", shared.ErrNotFound)
	}
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}
