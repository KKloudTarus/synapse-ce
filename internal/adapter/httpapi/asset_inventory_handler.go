package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/businessservice"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	assetuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assetinventory"
)

type assetInventoryService interface {
	CreateBusinessService(context.Context, assetuc.CreateBusinessServiceInput) (*businessservice.BusinessService, error)
	ListBusinessServices(context.Context, shared.ID) ([]*businessservice.BusinessService, error)
	CreateAsset(context.Context, assetuc.CreateAssetInput) (*asset.Asset, error)
	ListAssets(context.Context, shared.ID) ([]*asset.Asset, error)
	GetAsset(context.Context, shared.ID, shared.ID) (*asset.Asset, error)
	AddVersion(context.Context, string, shared.ID, shared.ID, string, string) (asset.Version, error)
	LinkBusinessServiceAsset(context.Context, string, shared.ID, shared.ID, shared.ID, asset.BusinessServiceRole) (asset.BusinessServiceLink, error)
	AddRelationship(context.Context, string, shared.ID, shared.ID, shared.ID, asset.RelationshipType) (asset.Relationship, error)
	ListRelationships(context.Context, shared.ID, shared.ID) ([]asset.Relationship, error)
}

func (rt *Router) SetAssetInventory(s assetInventoryService) { rt.assetInventory = s }

func decodeAssetInventoryJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(out); err != nil { writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"}); return false }
	return true
}
func (rt *Router) createBusinessService(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Code        string `json:"code"`
		Owner       string `json:"owner"`
		Criticality string `json:"criticality"`
	}
	if !decodeAssetInventoryJSON(w, r, &req) { return }
	s, err := rt.assetInventory.CreateBusinessService(r.Context(), assetuc.CreateBusinessServiceInput{TenantID: shared.ID(TenantFrom(r.Context())), Actor: PrincipalFrom(r.Context()), Name: req.Name, Code: req.Code, Owner: req.Owner, Criticality: req.Criticality})
	if err != nil { writeError(w, rt.log, err); return }
	writeJSON(w, http.StatusCreated, s)
}
func (rt *Router) listBusinessServices(w http.ResponseWriter,r *http.Request){out,err:=rt.assetInventory.ListBusinessServices(r.Context(),shared.ID(TenantFrom(r.Context())));if err!=nil{writeError(w,rt.log,err);return};writeJSON(w,http.StatusOK,out)}
func (rt *Router) createAsset(w http.ResponseWriter,r *http.Request){var req struct{Name string `json:"name"`;Category asset.Category `json:"category"`;Identity asset.Identity `json:"identity"`;Lifecycle asset.Lifecycle `json:"lifecycle"`;Owner string `json:"owner"`;Criticality string `json:"criticality"`;Exposure string `json:"exposure"`;Classification string `json:"classification"`};if !decodeAssetInventoryJSON(w,r,&req){return};a,err:=rt.assetInventory.CreateAsset(r.Context(),assetuc.CreateAssetInput{TenantID:shared.ID(TenantFrom(r.Context())),Actor:PrincipalFrom(r.Context()),Name:req.Name,Category:req.Category,Identity:req.Identity,Lifecycle:req.Lifecycle,Owner:req.Owner,Criticality:req.Criticality,Exposure:req.Exposure,Classification:req.Classification});if err!=nil{writeError(w,rt.log,err);return};writeJSON(w,http.StatusCreated,a)}
func (rt *Router) listAssets(w http.ResponseWriter,r *http.Request){out,err:=rt.assetInventory.ListAssets(r.Context(),shared.ID(TenantFrom(r.Context())));if err!=nil{writeError(w,rt.log,err);return};writeJSON(w,http.StatusOK,out)}
func (rt *Router) getAsset(w http.ResponseWriter,r *http.Request){a,err:=rt.assetInventory.GetAsset(r.Context(),shared.ID(TenantFrom(r.Context())),shared.ID(r.PathValue("id")));if err!=nil{writeError(w,rt.log,err);return};writeJSON(w,http.StatusOK,a)}
func (rt *Router) addAssetVersion(w http.ResponseWriter,r *http.Request){var req struct{Value string `json:"value"`;Source string `json:"source"`};if !decodeAssetInventoryJSON(w,r,&req){return};v,err:=rt.assetInventory.AddVersion(r.Context(),PrincipalFrom(r.Context()),shared.ID(TenantFrom(r.Context())),shared.ID(r.PathValue("id")),req.Value,req.Source);if err!=nil{writeError(w,rt.log,err);return};writeJSON(w,http.StatusCreated,v)}
func (rt *Router) linkBusinessServiceAsset(w http.ResponseWriter,r *http.Request){var req struct{AssetID shared.ID `json:"asset_id"`;Role asset.BusinessServiceRole `json:"role"`};if !decodeAssetInventoryJSON(w,r,&req){return};out,err:=rt.assetInventory.LinkBusinessServiceAsset(r.Context(),PrincipalFrom(r.Context()),shared.ID(TenantFrom(r.Context())),shared.ID(r.PathValue("id")),req.AssetID,req.Role);if err!=nil{writeError(w,rt.log,err);return};writeJSON(w,http.StatusCreated,out)}
func (rt *Router) addAssetRelationship(w http.ResponseWriter,r *http.Request){var req struct{ToAssetID shared.ID `json:"to_asset_id"`;Type asset.RelationshipType `json:"type"`};if !decodeAssetInventoryJSON(w,r,&req){return};out,err:=rt.assetInventory.AddRelationship(r.Context(),PrincipalFrom(r.Context()),shared.ID(TenantFrom(r.Context())),shared.ID(r.PathValue("id")),req.ToAssetID,req.Type);if err!=nil{writeError(w,rt.log,err);return};writeJSON(w,http.StatusCreated,out)}
func (rt *Router) listAssetRelationships(w http.ResponseWriter,r *http.Request){out,err:=rt.assetInventory.ListRelationships(r.Context(),shared.ID(TenantFrom(r.Context())),shared.ID(r.PathValue("id")));if err!=nil{writeError(w,rt.log,err);return};writeJSON(w,http.StatusOK,out)}
