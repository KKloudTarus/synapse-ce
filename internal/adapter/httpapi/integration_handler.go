package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	integrationuc "github.com/KKloudTarus/synapse-ce/internal/usecase/integrations"
)

type integrationDTO struct {
	ID                   shared.ID            `json:"id"`
	Provider             integration.Provider `json:"provider"`
	Name                 string               `json:"name"`
	Endpoint             string               `json:"endpoint"`
	Config               map[string]any       `json:"config"`
	AllowPrivateNetwork  bool                 `json:"allow_private_network"`
	PollIntervalSeconds  int64                `json:"poll_interval_seconds"`
	Enabled              bool                 `json:"enabled"`
	Archived             bool                 `json:"archived"`
	Version              int                  `json:"version"`
	CredentialConfigured bool                 `json:"credential_configured"`
	CreatedAt            time.Time            `json:"created_at"`
	UpdatedAt            time.Time            `json:"updated_at"`
}

func integrationResponse(item integration.Integration) integrationDTO {
	config, _ := integration.DecodeConfig(item.Config)
	return integrationDTO{
		ID: item.ID, Provider: item.Provider, Name: item.Name, Endpoint: item.Endpoint, Config: config,
		AllowPrivateNetwork: item.AllowPrivateNetwork, PollIntervalSeconds: int64(item.PollInterval / time.Second), Enabled: item.Enabled,
		Archived: item.Archived, Version: item.Version, CredentialConfigured: item.CredentialConfigured, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
	}
}

func (rt *Router) listIntegrationProviders(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, rt.integrations.ProviderDescriptors())
}

func (rt *Router) createIntegration(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Provider            string         `json:"provider"`
		Name                string         `json:"name"`
		Endpoint            string         `json:"endpoint"`
		Config              map[string]any `json:"config"`
		AllowPrivateNetwork bool           `json:"allow_private_network"`
		PollIntervalSeconds int64          `json:"poll_interval_seconds"`
	}
	if !decodeIntegrationJSON(w, r, &body) {
		return
	}
	item, err := rt.integrations.Create(r.Context(), integrationuc.CreateInput{
		TenantID: shared.ID(TenantFrom(r.Context())), Provider: body.Provider, Name: body.Name, Endpoint: body.Endpoint, Config: body.Config,
		AllowPrivateNetwork: body.AllowPrivateNetwork, PollInterval: time.Duration(body.PollIntervalSeconds) * time.Second, Actor: PrincipalFrom(r.Context()),
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, integrationResponse(item))
}

func (rt *Router) listIntegrations(w http.ResponseWriter, r *http.Request) {
	items, err := rt.integrations.List(r.Context(), shared.ID(TenantFrom(r.Context())), r.URL.Query().Get("include_archived") == "true")
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	response := make([]integrationDTO, len(items))
	for index, item := range items {
		response[index] = integrationResponse(item)
	}
	writeJSON(w, http.StatusOK, response)
}

func (rt *Router) getIntegration(w http.ResponseWriter, r *http.Request) {
	item, err := rt.integrations.Get(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, integrationResponse(item))
}

func (rt *Router) updateIntegration(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name                string         `json:"name"`
		Endpoint            string         `json:"endpoint"`
		Config              map[string]any `json:"config"`
		AllowPrivateNetwork bool           `json:"allow_private_network"`
		PollIntervalSeconds int64          `json:"poll_interval_seconds"`
		Version             int            `json:"version"`
	}
	if !decodeIntegrationJSON(w, r, &body) {
		return
	}
	item, err := rt.integrations.Update(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")), integrationuc.UpdateInput{
		Name: body.Name, Endpoint: body.Endpoint, Config: body.Config, AllowPrivateNetwork: body.AllowPrivateNetwork,
		PollInterval: time.Duration(body.PollIntervalSeconds) * time.Second, Version: body.Version, Actor: PrincipalFrom(r.Context()),
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, integrationResponse(item))
}

func (rt *Router) enableIntegration(w http.ResponseWriter, r *http.Request) {
	rt.setIntegrationEnabled(w, r, true)
}

func (rt *Router) disableIntegration(w http.ResponseWriter, r *http.Request) {
	rt.setIntegrationEnabled(w, r, false)
}

func (rt *Router) setIntegrationEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	var body struct {
		Version int `json:"version"`
	}
	if !decodeIntegrationJSON(w, r, &body) {
		return
	}
	item, err := rt.integrations.SetEnabled(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")), enabled, body.Version, PrincipalFrom(r.Context()))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, integrationResponse(item))
}

func (rt *Router) archiveIntegration(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Version int `json:"version"`
	}
	if !decodeIntegrationJSON(w, r, &body) {
		return
	}
	if err := rt.integrations.Archive(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")), body.Version, PrincipalFrom(r.Context())); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (rt *Router) putIntegrationCredential(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Secrets map[string]string `json:"secrets"`
	}
	if !decodeIntegrationJSON(w, r, &body) {
		return
	}
	if err := rt.integrations.SetCredential(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")), body.Secrets, PrincipalFrom(r.Context())); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (rt *Router) deleteIntegrationCredential(w http.ResponseWriter, r *http.Request) {
	if err := rt.integrations.DeleteCredential(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")), PrincipalFrom(r.Context())); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (rt *Router) startIntegrationOperation(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Type integration.OperationType `json:"type"`
	}
	if !decodeIntegrationJSON(w, r, &body) {
		return
	}
	operation, err := rt.integrations.StartOperation(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")), body.Type, PrincipalFrom(r.Context()))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusAccepted, operation)
}

func (rt *Router) listIntegrationOperations(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	operations, err := rt.integrations.ListOperations(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")), limit)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, operations)
}

func (rt *Router) getIntegrationOperation(w http.ResponseWriter, r *http.Request) {
	operation, err := rt.integrations.GetOperation(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("operationID")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, operation)
}

func (rt *Router) cancelIntegrationOperation(w http.ResponseWriter, r *http.Request) {
	operation, err := rt.integrations.CancelOperation(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("operationID")), PrincipalFrom(r.Context()))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, operation)
}

func (rt *Router) createIntegrationBinding(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ProjectID    shared.ID `json:"project_id"`
		ExternalKey  string    `json:"external_key"`
		ExternalName string    `json:"external_name"`
	}
	if !decodeIntegrationJSON(w, r, &body) {
		return
	}
	binding, err := rt.integrations.CreateBinding(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")), body.ProjectID, body.ExternalKey, body.ExternalName, PrincipalFrom(r.Context()))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, binding)
}

func (rt *Router) listIntegrationBindings(w http.ResponseWriter, r *http.Request) {
	bindings, err := rt.integrations.ListBindings(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, bindings)
}

func (rt *Router) deleteIntegrationBinding(w http.ResponseWriter, r *http.Request) {
	if err := rt.integrations.DeleteBinding(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")), shared.ID(r.PathValue("bindingID")), PrincipalFrom(r.Context())); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (rt *Router) listIntegrationExternalRuns(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	runs, err := rt.integrations.ListExternalRuns(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("id")), limit)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, runs)
}

func decodeIntegrationJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: fmt.Sprintf("invalid request: %v", err)})
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request: exactly one JSON object is required"})
		return false
	}
	return true
}
