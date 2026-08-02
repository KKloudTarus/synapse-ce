package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	assessmentuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentuc"
)

type createAssessmentRequest struct {
	Name      string            `json:"name"`
	Objective string            `json:"objective"`
	Policy    assessment.Policy `json:"policy"`
	Assets    []struct {
		Name   string `json:"name"`
		Client string `json:"client"`
	} `json:"assets"`
}

type assessmentResponse struct {
	ID                string            `json:"id"`
	BusinessServiceID string            `json:"business_service_id"`
	Name              string            `json:"name"`
	Objective         string            `json:"objective"`
	Status            assessment.Status `json:"status"`
	Policy            assessment.Policy `json:"policy"`
}

type assessmentAssetResponse struct {
	ID           string `json:"id"`
	AssessmentID string `json:"assessment_id"`
	Name         string `json:"name"`
	Client       string `json:"client"`
	Status       string `json:"status"`
}

func assessmentDTO(a assessment.Assessment) assessmentResponse {
	return assessmentResponse{ID: a.ID.String(), BusinessServiceID: a.BusinessServiceID.String(), Name: a.Name, Objective: a.Objective, Status: a.Status, Policy: a.Policy}
}

func (rt *Router) createAssessment(w http.ResponseWriter, r *http.Request) {
	var req createAssessmentRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	children := make([]assessmentuc.AssetInput, len(req.Assets))
	for i, asset := range req.Assets {
		children[i] = assessmentuc.AssetInput{Name: asset.Name, Client: asset.Client}
	}
	a, err := rt.assessments.Create(r.Context(), assessmentuc.CreateInput{TenantID: shared.ID(TenantFrom(r.Context())), BusinessServiceID: shared.ID(r.PathValue("sid")), Actor: PrincipalFrom(r.Context()), Name: req.Name, Objective: req.Objective, Policy: req.Policy, Assets: children})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, assessmentDTO(a))
}
func (rt *Router) listAssessments(w http.ResponseWriter, r *http.Request) {
	items, err := rt.assessments.List(r.Context(), shared.ID(r.PathValue("sid")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]assessmentResponse, len(items))
	for i, item := range items {
		out[i] = assessmentDTO(item)
	}
	writeJSON(w, http.StatusOK, out)
}
func (rt *Router) getAssessment(w http.ResponseWriter, r *http.Request) {
	a, err := rt.assessments.Get(r.Context(), shared.ID(r.PathValue("sid")), shared.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, assessmentDTO(a))
}

func (rt *Router) listAssessmentAssets(w http.ResponseWriter, r *http.Request) {
	serviceID, assessmentID := shared.ID(r.PathValue("sid")), shared.ID(r.PathValue("id"))
	if _, err := rt.assessments.Get(r.Context(), serviceID, assessmentID); err != nil {
		writeError(w, rt.log, err)
		return
	}
	items, err := rt.eng.List(r.Context(), shared.ID(TenantFrom(r.Context())))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]assessmentAssetResponse, 0)
	for _, item := range items {
		if item.AssessmentID == assessmentID {
			out = append(out, assessmentAssetResponse{ID: item.ID.String(), AssessmentID: assessmentID.String(), Name: item.Name, Client: item.Client, Status: string(item.Status)})
		}
	}
	writeJSON(w, http.StatusOK, out)
}
