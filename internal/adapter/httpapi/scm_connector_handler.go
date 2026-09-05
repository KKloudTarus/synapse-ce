package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scmconnector"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/scmconnectoruc"
)

// connectorService is the slice of the source-control connector use case the HTTP layer drives:
// create (token write-only), list (metadata only), and delete. *scmconnectoruc.Service satisfies
// it. Left unset, the routes are not registered, like every other optional subsystem.
type connectorService interface {
	Create(ctx context.Context, in scmconnectoruc.CreateInput) (ports.SCMConnectorMeta, error)
	List(ctx context.Context) ([]ports.SCMConnectorMeta, error)
	Delete(ctx context.Context, id shared.ID) error
}

// SetConnectors wires the source-control connector routes. The token entered on create is sealed
// by the store and never returned, so these routes need PermAdminister (below, in the router).
func (rt *Router) SetConnectors(svc connectorService) {
	if svc != nil {
		rt.connectors = svc
	}
}

type connectorCreateRequest struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Host     string `json:"host"`
	Username string `json:"username"`
	Token    string `json:"token"` // write-only: sealed by the store, never returned
}

// connectorDTO is the non-secret view returned to the client. It never carries the token.
type connectorDTO struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Provider  string    `json:"provider"`
	Host      string    `json:"host"`
	Username  string    `json:"username"`
	AuthKind  string    `json:"auth_kind"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func toConnectorDTO(m ports.SCMConnectorMeta) connectorDTO {
	return connectorDTO{
		ID: m.ID.String(), Name: m.Name, Provider: string(m.Provider), Host: m.Host,
		Username: m.Username, AuthKind: string(m.AuthKind), CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt,
	}
}

// createConnector stores a tenant-scoped source-control connector. The token is write-only: it is
// sealed by the store and the 201 body carries only metadata.
func (rt *Router) createConnector(w http.ResponseWriter, r *http.Request) {
	var req connectorCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	tenant := requestTenant(r)
	ctx := shared.WithTenant(r.Context(), tenant)
	meta, err := rt.connectors.Create(ctx, scmconnectoruc.CreateInput{
		TenantID: tenant,
		Name:     req.Name,
		Provider: scmconnector.Provider(req.Provider),
		Host:     req.Host,
		Username: req.Username,
		Token:    req.Token,
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, toConnectorDTO(meta))
}

// listConnectors returns the tenant's connectors as metadata (never the token).
func (rt *Router) listConnectors(w http.ResponseWriter, r *http.Request) {
	ctx := shared.WithTenant(r.Context(), requestTenant(r))
	metas, err := rt.connectors.List(ctx)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]connectorDTO, 0, len(metas))
	for _, m := range metas {
		out = append(out, toConnectorDTO(m))
	}
	writeJSON(w, http.StatusOK, map[string]any{"connectors": out})
}

// deleteConnector removes a connector by id under the caller's tenant.
func (rt *Router) deleteConnector(w http.ResponseWriter, r *http.Request) {
	ctx := shared.WithTenant(r.Context(), requestTenant(r))
	if err := rt.connectors.Delete(ctx, shared.ID(r.PathValue("id"))); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
