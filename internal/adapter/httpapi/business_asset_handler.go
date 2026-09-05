package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/businessassetuc"
)

type businessAssetService interface {
	Create(context.Context, businessassetuc.CreateInput) (*asset.BusinessAsset, error)
	Update(context.Context, shared.ID, shared.ID, businessassetuc.UpdateInput) (*asset.BusinessAsset, error)
	Get(context.Context, shared.ID, shared.ID) (*asset.BusinessAsset, error)
	List(context.Context, shared.ID, businessassetuc.Filter) ([]*asset.BusinessAsset, error)
	ReplaceProjects(context.Context, shared.ID, shared.ID, []asset.ComponentMembership, string) error
	Projects(context.Context, shared.ID, shared.ID) ([]asset.ComponentMembership, error)
	ReplaceTechnicalAssets(context.Context, shared.ID, shared.ID, []asset.ComponentMembership, string) error
	TechnicalAssets(context.Context, shared.ID, shared.ID) ([]asset.ComponentMembership, error)
	AssignEngagement(context.Context, shared.ID, shared.ID, shared.ID, string) error
	Engagements(context.Context, shared.ID, shared.ID) ([]*engagement.Engagement, error)
	Findings(context.Context, shared.ID, shared.ID) ([]businessassetuc.AggregatedFinding, error)
	Coverage(context.Context, shared.ID, shared.ID) (businessassetuc.Coverage, error)
	Posture(context.Context, shared.ID, shared.ID) (businessassetuc.Posture, error)
	History(context.Context, shared.ID, shared.ID) ([]businessassetuc.HistoryItem, error)
}

func (rt *Router) SetBusinessAssets(service businessAssetService) { rt.businessAssets = service }
func requestTenant(r *http.Request) shared.ID {
	return shared.TenantOrDefault(shared.ID(TenantFrom(r.Context())))
}

type businessAssetRequest struct {
	Key         string                       `json:"key"`
	Name        string                       `json:"name"`
	Description string                       `json:"description"`
	Type        asset.BusinessAssetType      `json:"type"`
	Criticality asset.Criticality            `json:"criticality"`
	Lifecycle   asset.BusinessAssetLifecycle `json:"lifecycle"`
	Owner       string                       `json:"owner"`
	Metadata    map[string]string            `json:"metadata"`
	Version     int                          `json:"version"`
}
type businessAssetListItem struct {
	*asset.BusinessAsset
	Posture            string `json:"posture"`
	PostureExplanation string `json:"posture_explanation"`
}

func (rt *Router) createBusinessAsset(w http.ResponseWriter, r *http.Request) {
	var req businessAssetRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, assetBodyCap)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid asset body"})
		return
	}
	a, err := rt.businessAssets.Create(r.Context(), businessassetuc.CreateInput{TenantID: requestTenant(r), Key: req.Key, Name: req.Name, Description: req.Description, Type: req.Type, Criticality: req.Criticality, Owner: req.Owner, Metadata: req.Metadata, Actor: PrincipalFrom(r.Context())})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, a)
}
func (rt *Router) listBusinessAssets(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 200 {
			limit = n
		} else {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "limit must be 1..200"})
			return
		}
	}
	offset := 0
	if raw := r.URL.Query().Get("offset"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "offset must be non-negative"})
			return
		}
		offset = n
	}
	items, err := rt.businessAssets.List(r.Context(), requestTenant(r), businessassetuc.Filter{Query: r.URL.Query().Get("q"), Type: asset.BusinessAssetType(r.URL.Query().Get("type")), Criticality: asset.Criticality(r.URL.Query().Get("criticality")), Lifecycle: asset.BusinessAssetLifecycle(r.URL.Query().Get("lifecycle")), Owner: r.URL.Query().Get("owner")})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if offset > len(items) {
		offset = len(items)
	}
	end := min(offset+limit, len(items))
	out := make([]businessAssetListItem, 0, end-offset)
	for _, a := range items[offset:end] {
		posture, pErr := rt.businessAssets.Posture(r.Context(), requestTenant(r), a.ID)
		if pErr != nil {
			writeError(w, rt.log, pErr)
			return
		}
		out = append(out, businessAssetListItem{BusinessAsset: a, Posture: posture.Rating, PostureExplanation: posture.Explanation})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "total": len(items), "limit": limit, "offset": offset})
}
func (rt *Router) getBusinessAsset(w http.ResponseWriter, r *http.Request) {
	a, err := rt.businessAssets.Get(r.Context(), requestTenant(r), shared.ID(r.PathValue("assetID")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}
func (rt *Router) updateBusinessAsset(w http.ResponseWriter, r *http.Request) {
	var req businessAssetRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, assetBodyCap)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid asset body"})
		return
	}
	a, err := rt.businessAssets.Update(r.Context(), requestTenant(r), shared.ID(r.PathValue("assetID")), businessassetuc.UpdateInput{Name: req.Name, Description: req.Description, Type: req.Type, Criticality: req.Criticality, Owner: req.Owner, Metadata: req.Metadata, Lifecycle: req.Lifecycle, Version: req.Version, Actor: PrincipalFrom(r.Context())})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

type membershipRequest struct {
	Items []struct {
		ID         string               `json:"id"`
		Role       asset.MembershipRole `json:"role"`
		Provenance string               `json:"provenance"`
	} `json:"items"`
}

func membershipLinks(req membershipRequest) []asset.ComponentMembership {
	out := make([]asset.ComponentMembership, 0, len(req.Items))
	for _, item := range req.Items {
		out = append(out, asset.ComponentMembership{ComponentID: shared.ID(item.ID), Role: item.Role, Provenance: item.Provenance})
	}
	return out
}
func (rt *Router) putBusinessAssetProjects(w http.ResponseWriter, r *http.Request) {
	var req membershipRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, assetBodyCap)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid membership body"})
		return
	}
	if err := rt.businessAssets.ReplaceProjects(r.Context(), requestTenant(r), shared.ID(r.PathValue("assetID")), membershipLinks(req), PrincipalFrom(r.Context())); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (rt *Router) getBusinessAssetProjects(w http.ResponseWriter, r *http.Request) {
	rows, err := rt.businessAssets.Projects(r.Context(), requestTenant(r), shared.ID(r.PathValue("assetID")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}
func (rt *Router) putBusinessAssetTechnicalAssets(w http.ResponseWriter, r *http.Request) {
	var req membershipRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, assetBodyCap)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid membership body"})
		return
	}
	if err := rt.businessAssets.ReplaceTechnicalAssets(r.Context(), requestTenant(r), shared.ID(r.PathValue("assetID")), membershipLinks(req), PrincipalFrom(r.Context())); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (rt *Router) getBusinessAssetTechnicalAssets(w http.ResponseWriter, r *http.Request) {
	rows, err := rt.businessAssets.TechnicalAssets(r.Context(), requestTenant(r), shared.ID(r.PathValue("assetID")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}
func (rt *Router) getBusinessAssetEngagements(w http.ResponseWriter, r *http.Request) {
	rows, err := rt.businessAssets.Engagements(r.Context(), requestTenant(r), shared.ID(r.PathValue("assetID")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, toEngagementViews(rows))
}
func (rt *Router) assignEngagementBusinessAsset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AssetID string `json:"asset_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, assetBodyCap)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid assignment body"})
		return
	}
	if err := rt.businessAssets.AssignEngagement(r.Context(), requestTenant(r), shared.ID(r.PathValue("id")), shared.ID(req.AssetID), PrincipalFrom(r.Context())); err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (rt *Router) getBusinessAssetFindings(w http.ResponseWriter, r *http.Request) {
	rows, err := rt.businessAssets.Findings(r.Context(), requestTenant(r), shared.ID(r.PathValue("assetID")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}
func (rt *Router) getBusinessAssetCoverage(w http.ResponseWriter, r *http.Request) {
	row, err := rt.businessAssets.Coverage(r.Context(), requestTenant(r), shared.ID(r.PathValue("assetID")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, row)
}
func (rt *Router) getBusinessAssetPosture(w http.ResponseWriter, r *http.Request) {
	row, err := rt.businessAssets.Posture(r.Context(), requestTenant(r), shared.ID(r.PathValue("assetID")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, row)
}
func (rt *Router) getBusinessAssetHistory(w http.ResponseWriter, r *http.Request) {
	rows, err := rt.businessAssets.History(r.Context(), requestTenant(r), shared.ID(r.PathValue("assetID")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}
