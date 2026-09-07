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
	Workloads(context.Context, shared.ID) ([]assetuc.WorkloadOrigin, error)
}

// SetAssets wires the asset service and enables the asset routes.
func (rt *Router) SetAssets(s assetService) { rt.assets = s }

const assetBodyCap = 64 << 10

// DefaultFleetTenant is the non-empty tenant id used when the principal is on the empty-string
// default tenant (single-tenant deployments). RLS-protected fleet tables cannot use the empty
// string, because under the 0057 policy the empty string is DENY, not a tenant. Mapping the empty
// default to a real, non-empty tenant here is what lets the fleet asset model work in a
// single-tenant deployment while still being isolated at the database. Migration 0058 seeds this
// tenant row so the fleet_assets FK to tenants is satisfied. It aliases shared.DefaultTenant (the
// inner-layer canonical value) so the two cannot drift.
const DefaultFleetTenant = shared.DefaultTenant

// fleetTenant resolves the effective tenant for fleet asset operations: the request principal's
// tenant, or DefaultFleetTenant when that is the empty-string default tenant.
func fleetTenant(ctx context.Context) shared.ID {
	if t := TenantFrom(ctx); t != "" {
		return shared.ID(t)
	}
	return DefaultFleetTenant
}

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
		TenantID:   fleetTenant(r.Context()),
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
	list, err := rt.assets.ListAssets(r.Context(), fleetTenant(r.Context()))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if list == nil {
		list = []*asset.Asset{}
	}
	writeJSON(w, http.StatusOK, list)
}

type upsertEdgeRequest struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Kind       string `json:"kind"`
	Provenance string `json:"provenance"`
	Confidence string `json:"confidence"`
}

func (rt *Router) createAssetEdge(w http.ResponseWriter, r *http.Request) {
	var req upsertEdgeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, assetBodyCap)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid edge body"})
		return
	}
	if err := rt.assets.UpsertEdge(r.Context(), PrincipalFrom(r.Context()), assetuc.EdgeInput{
		TenantID:   fleetTenant(r.Context()),
		From:       shared.ID(req.From),
		To:         shared.ID(req.To),
		Kind:       asset.EdgeKind(req.Kind),
		Provenance: shared.ID(req.Provenance),
		Confidence: asset.EdgeConfidence(req.Confidence),
	}); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (rt *Router) listAssetEdges(w http.ResponseWriter, r *http.Request) {
	list, err := rt.assets.ListEdges(r.Context(), fleetTenant(r.Context()))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if list == nil {
		list = []*asset.Edge{}
	}
	writeJSON(w, http.StatusOK, list)
}

type workloadImageDTO struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

// workloadOriginDTO is one Kubernetes workload and the images it runs, from the cluster-inventory
// graph. It lets an operator trace a container CVE (found on an image) back to the workload that runs
// it: the deployment, statefulset, daemonset, and namespace it came from.
type workloadOriginDTO struct {
	Cluster        string             `json:"cluster"`
	Namespace      string             `json:"namespace"`
	Kind           string             `json:"kind"`
	Name           string             `json:"name"`
	ServiceAccount string             `json:"service_account,omitempty"`
	Images         []workloadImageDTO `json:"images"`
}

// listFleetWorkloads returns the tenant's Kubernetes workloads with the images they run, so a CVE on
// an image can be traced to its workload origin. Empty until a cluster agent ingests a snapshot.
func (rt *Router) listFleetWorkloads(w http.ResponseWriter, r *http.Request) {
	list, err := rt.assets.Workloads(r.Context(), fleetTenant(r.Context()))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]workloadOriginDTO, 0, len(list))
	for _, wl := range list {
		dto := workloadOriginDTO{Cluster: wl.Cluster, Namespace: wl.Namespace, Kind: wl.Kind, Name: wl.Name, ServiceAccount: wl.ServiceAccount, Images: []workloadImageDTO{}}
		for _, img := range wl.Images {
			dto.Images = append(dto.Images, workloadImageDTO{Ref: img.Ref, Digest: img.Digest})
		}
		out = append(out, dto)
	}
	writeJSON(w, http.StatusOK, map[string]any{"workloads": out})
}
