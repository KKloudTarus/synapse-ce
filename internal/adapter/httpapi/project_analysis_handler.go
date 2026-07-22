package httpapi

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rating"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type projectGateConditionResponse struct {
	Metric    string  `json:"metric"`
	Op        string  `json:"op"`
	Threshold float64 `json:"threshold"`
	Actual    float64 `json:"actual"`
	Passed    bool    `json:"passed"`
}

type projectGateResponse struct {
	Passed  bool                           `json:"passed"`
	Results []projectGateConditionResponse `json:"results"`
}

type projectAnalysisResponse struct {
	ID             string                             `json:"id"`
	CreatedAt      time.Time                          `json:"created_at"`
	SourceRef      string                             `json:"source_ref,omitempty"`
	SourceCommit   string                             `json:"source_commit,omitempty"`
	SourceRevision projectanalysis.SourceRevision     `json:"source_revision,omitempty"`
	Capabilities   projectanalysis.SourceCapabilities `json:"capabilities"`
	Gate           projectGateResponse                `json:"gate"`
	GateInfo       projectanalysis.GateInfo           `json:"gate_info"`
	Issues         projectanalysis.Counts             `json:"issues"`
	NewCode        projectanalysis.NewCode            `json:"new_code"`
	Delta          *projectanalysis.Delta             `json:"delta"`
	Measures       qualitygate.Snapshot               `json:"measures"`
	Coverage       *measure.CoverageReport            `json:"coverage"`
	Duplication    measure.DuplicationReport          `json:"duplication"`
	Rating         rating.Report                      `json:"rating"`
}

func projectAnalysisDTO(analysis projectanalysis.Analysis) projectAnalysisResponse {
	gate := projectGateResponse{Passed: analysis.Gate.Passed, Results: make([]projectGateConditionResponse, len(analysis.Gate.Results))}
	for i, result := range analysis.Gate.Results {
		gate.Results[i] = projectGateConditionResponse{Metric: result.Condition.Metric, Op: string(result.Condition.Op), Threshold: result.Condition.Threshold, Actual: result.Actual, Passed: result.Passed}
	}
	return projectAnalysisResponse{
		ID: analysis.ID, CreatedAt: analysis.CreatedAt, SourceRef: analysis.SourceRef, SourceCommit: analysis.SourceCommit,
		SourceRevision: analysis.SourceRevision, Capabilities: analysis.Capabilities,
		Gate: gate, GateInfo: analysis.GateInfo, Issues: analysis.Issues, NewCode: analysis.NewCode, Delta: analysis.Delta,
		Measures: analysis.Measures, Coverage: analysis.Coverage, Duplication: analysis.Duplication, Rating: analysis.Rating,
	}
}

type projectAnalysisCursorResponse struct {
	BeforeCreatedAt time.Time `json:"before_created_at"`
	BeforeID        string    `json:"before_id"`
}

type projectAnalysisPageResponse struct {
	Items []projectAnalysisResponse      `json:"items"`
	Next  *projectAnalysisCursorResponse `json:"next"`
}

func (rt *Router) listProjectAnalyses(w http.ResponseWriter, r *http.Request) {
	limit, beforeCreatedAt, beforeID, err := projectAnalysisPageParams(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	analyses, hasMore, err := rt.projects.ListAnalyses(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), limit, beforeCreatedAt, beforeID)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := projectAnalysisPageResponse{Items: make([]projectAnalysisResponse, len(analyses))}
	for i, analysis := range analyses {
		out.Items[i] = projectAnalysisDTO(analysis)
	}
	if hasMore && len(analyses) > 0 {
		last := analyses[len(analyses)-1]
		out.Next = &projectAnalysisCursorResponse{BeforeCreatedAt: last.CreatedAt, BeforeID: last.ID}
	}
	writeJSON(w, http.StatusOK, out)
}

func projectAnalysisPageParams(r *http.Request) (int, time.Time, shared.ID, error) {
	limit := 25
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			return 0, time.Time{}, "", fmt.Errorf("%w: limit must be between 1 and 100", shared.ErrValidation)
		}
		limit = parsed
	}
	rawTime := strings.TrimSpace(r.URL.Query().Get("before_created_at"))
	rawID := strings.TrimSpace(r.URL.Query().Get("before_id"))
	if (rawTime == "") != (rawID == "") {
		return 0, time.Time{}, "", fmt.Errorf("%w: before_created_at and before_id must be supplied together", shared.ErrValidation)
	}
	if rawTime == "" {
		return limit, time.Time{}, "", nil
	}
	before, err := time.Parse(time.RFC3339Nano, rawTime)
	if err != nil {
		return 0, time.Time{}, "", fmt.Errorf("%w: before_created_at must be RFC3339", shared.ErrValidation)
	}
	return limit, before, shared.ID(rawID), nil
}

func (rt *Router) getProjectAnalysis(w http.ResponseWriter, r *http.Request) {
	analysis, err := rt.projects.GetAnalysis(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), r.PathValue("id"))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, projectAnalysisDTO(analysis))
}
