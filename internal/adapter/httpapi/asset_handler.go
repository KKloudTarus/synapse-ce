package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/assetuc"
)

// assetService is the narrow view of the asset use case the HTTP layer needs. It is optional: when
// nil, the asset routes are not registered (see router.go).
type assetService interface {
	UpsertAsset(context.Context, string, assetuc.UpsertAssetInput) (*asset.Asset, error)
	ListAssets(context.Context, shared.ID) ([]*asset.Asset, error)
	UpsertEdge(context.Context, string, assetuc.EdgeInput) error
	ListEdges(context.Context, shared.ID) ([]*asset.Edge, error)
	UpsertBusinessService(context.Context, string, assetuc.BusinessServiceInput) (*asset.BusinessService, error)
	ListBusinessServices(context.Context, shared.ID) ([]*asset.BusinessService, error)
}

// SetAssets wires the asset service and enables the asset routes.
func (rt *Router) SetAssets(s assetService) { rt.assets = s }

const assetBodyCap = 64 << 10

type upsertAssetRequest struct {
	Kind       string            `json:"kind"`
	Key        string            `json:"key"`
	Name       string            `json:"name"`
	Attributes map[string]string `json:"attributes"`
}

func (rt *Router) createAsset(w http.ResponseWriter, r *http.Request) {
	var req upsertAssetRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, assetBodyCap)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid asset body"})
		return
	}
	a, err := rt.assets.UpsertAsset(r.Context(), PrincipalFrom(r.Context()), assetuc.UpsertAssetInput{
		TenantID:   shared.ID(TenantFrom(r.Context())),
		Kind:       asset.Kind(req.Kind),
		Key:        req.Key,
		Name:       req.Name,
		Attributes: req.Attributes,
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (rt *Router) listAssets(w http.ResponseWriter, r *http.Request) {
	list, err := rt.assets.ListAssets(r.Context(), shared.ID(TenantFrom(r.Context())))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

type upsertEdgeRequest struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Kind       string `json:"kind"`
	Provenance string `json:"provenance"`
}

func (rt *Router) createAssetEdge(w http.ResponseWriter, r *http.Request) {
	var req upsertEdgeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, assetBodyCap)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid edge body"})
		return
	}
	if err := rt.assets.UpsertEdge(r.Context(), PrincipalFrom(r.Context()), assetuc.EdgeInput{
		TenantID:   shared.ID(TenantFrom(r.Context())),
		From:       shared.ID(req.From),
		To:         shared.ID(req.To),
		Kind:       asset.EdgeKind(req.Kind),
		Provenance: shared.ID(req.Provenance),
	}); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (rt *Router) listAssetEdges(w http.ResponseWriter, r *http.Request) {
	list, err := rt.assets.ListEdges(r.Context(), shared.ID(TenantFrom(r.Context())))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

type upsertServiceRequest struct {
	Name  string `json:"name"`
	Owner string `json:"owner"`
}

func (rt *Router) createBusinessService(w http.ResponseWriter, r *http.Request) {
	var req upsertServiceRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, assetBodyCap)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid business service body"})
		return
	}
	svc, err := rt.assets.UpsertBusinessService(r.Context(), PrincipalFrom(r.Context()), assetuc.BusinessServiceInput{
		TenantID: shared.ID(TenantFrom(r.Context())),
		Name:     req.Name,
		Owner:    req.Owner,
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, svc)
}

func (rt *Router) listBusinessServices(w http.ResponseWriter, r *http.Request) {
	list, err := rt.assets.ListBusinessServices(r.Context(), shared.ID(TenantFrom(r.Context())))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}
