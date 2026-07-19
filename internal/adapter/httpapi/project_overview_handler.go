package httpapi

import (
	"net/http"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

type projectOverviewResponse struct {
	State          string                      `json:"state"`
	Project        projectOverviewProjectDTO   `json:"project"`
	LatestAnalysis *projectOverviewAnalysisDTO `json:"latest_analysis"`
	Gate           *projectOverviewGateDTO     `json:"gate"`
	IssueSummary   projectOverviewIssuesDTO    `json:"issue_summary"`
	Lenses         projectOverviewLensesDTO    `json:"lenses"`
}

type projectOverviewProjectDTO struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type projectOverviewAnalysisDTO struct {
	ID           string                          `json:"id"`
	CreatedAt    time.Time                       `json:"created_at"`
	SourceRef    string                          `json:"source_ref"`
	SourceCommit string                          `json:"source_commit"`
	NewCode      projectOverviewNewCodePeriodDTO `json:"new_code"`
}

type projectOverviewNewCodePeriodDTO struct {
	FirstAnalysis      bool    `json:"first_analysis"`
	HasBaseline        bool    `json:"has_baseline"`
	BaselineAnalysisID *string `json:"baseline_analysis_id"`
}

type projectOverviewGateDTO struct {
	Status           string                            `json:"status"`
	Key              *string                           `json:"key"`
	Name             *string                           `json:"name"`
	Source           *string                           `json:"source"`
	FailedConditions []projectOverviewGateConditionDTO `json:"failed_conditions"`
}

type projectOverviewGateConditionDTO struct {
	Metric    string  `json:"metric"`
	Operator  string  `json:"operator"`
	Threshold float64 `json:"threshold"`
	Actual    float64 `json:"actual"`
}

type projectOverviewIssuesDTO struct {
	NewCodeTotal         projectOverviewCountMetricDTO `json:"new_code_total"`
	AcceptedOverallTotal projectOverviewCountMetricDTO `json:"accepted_overall_total"`
}

type projectOverviewLensesDTO struct {
	Overall projectOverviewLensDTO `json:"overall"`
	NewCode projectOverviewLensDTO `json:"new_code"`
}

type projectOverviewLensDTO struct {
	Security                 projectOverviewRatingMetricDTO     `json:"security"`
	Reliability              projectOverviewRatingMetricDTO     `json:"reliability"`
	Maintainability          projectOverviewRatingMetricDTO     `json:"maintainability"`
	SecurityHotspotsReviewed projectOverviewPercentageMetricDTO `json:"security_hotspots_reviewed"`
	Coverage                 projectOverviewPercentageMetricDTO `json:"coverage"`
	Duplications             projectOverviewPercentageMetricDTO `json:"duplications"`
}

type projectOverviewRatingMetricDTO struct {
	Availability      string  `json:"availability"`
	Grade             *string `json:"grade"`
	UnavailableReason *string `json:"unavailable_reason"`
}

type projectOverviewPercentageMetricDTO struct {
	Availability      string   `json:"availability"`
	Value             *float64 `json:"value"`
	Grade             *string  `json:"grade,omitempty"`
	UnavailableReason *string  `json:"unavailable_reason"`
}

type projectOverviewCountMetricDTO struct {
	Availability      string  `json:"availability"`
	Value             *int    `json:"value"`
	UnavailableReason *string `json:"unavailable_reason"`
}

func (rt *Router) projectOverview(w http.ResponseWriter, r *http.Request) {
	overview, err := rt.projects.Overview(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, projectOverviewDTO(overview))
}

func projectOverviewDTO(overview projectuc.Overview) projectOverviewResponse {
	var latest *projectOverviewAnalysisDTO
	if overview.LatestAnalysis != nil {
		latest = &projectOverviewAnalysisDTO{
			ID:           overview.LatestAnalysis.ID,
			CreatedAt:    overview.LatestAnalysis.CreatedAt,
			SourceRef:    overview.LatestAnalysis.SourceRef,
			SourceCommit: overview.LatestAnalysis.SourceCommit,
			NewCode: projectOverviewNewCodePeriodDTO{
				FirstAnalysis:      overview.LatestAnalysis.NewCode.FirstAnalysis,
				HasBaseline:        overview.LatestAnalysis.NewCode.HasBaseline,
				BaselineAnalysisID: overview.LatestAnalysis.NewCode.BaselineAnalysisID,
			},
		}
	}
	var gate *projectOverviewGateDTO
	if overview.Gate != nil {
		gate = &projectOverviewGateDTO{
			Status:           string(overview.Gate.Status),
			Key:              overview.Gate.Key,
			Name:             overview.Gate.Name,
			Source:           overviewGateSourceString(overview.Gate.Source),
			FailedConditions: make([]projectOverviewGateConditionDTO, len(overview.Gate.FailedConditions)),
		}
		for i, condition := range overview.Gate.FailedConditions {
			gate.FailedConditions[i] = projectOverviewGateConditionDTO{
				Metric: condition.Metric, Operator: string(condition.Operator),
				Threshold: condition.Threshold, Actual: condition.Actual,
			}
		}
	}
	return projectOverviewResponse{
		State: string(overview.State),
		Project: projectOverviewProjectDTO{
			Key:  overview.Project.Key,
			Name: overview.Project.Name,
		},
		LatestAnalysis: latest,
		Gate:           gate,
		IssueSummary: projectOverviewIssuesDTO{
			NewCodeTotal:         projectOverviewCountMetricDTOFromUsecase(overview.IssueSummary.NewCodeTotal),
			AcceptedOverallTotal: projectOverviewCountMetricDTOFromUsecase(overview.IssueSummary.AcceptedOverallTotal),
		},
		Lenses: projectOverviewLensesDTO{
			Overall: projectOverviewLensDTOFromUsecase(overview.Overall),
			NewCode: projectOverviewLensDTOFromUsecase(overview.NewCode),
		},
	}
}

func projectOverviewLensDTOFromUsecase(lens projectuc.OverviewLens) projectOverviewLensDTO {
	return projectOverviewLensDTO{
		Security:                 projectOverviewRatingMetricDTOFromUsecase(lens.Security),
		Reliability:              projectOverviewRatingMetricDTOFromUsecase(lens.Reliability),
		Maintainability:          projectOverviewRatingMetricDTOFromUsecase(lens.Maintainability),
		SecurityHotspotsReviewed: projectOverviewPercentageMetricDTOFromUsecase(lens.SecurityHotspotsReviewed),
		Coverage:                 projectOverviewPercentageMetricDTOFromUsecase(lens.Coverage),
		Duplications:             projectOverviewPercentageMetricDTOFromUsecase(lens.Duplications),
	}
}

func projectOverviewRatingMetricDTOFromUsecase(metric projectuc.RatingMetric) projectOverviewRatingMetricDTO {
	return projectOverviewRatingMetricDTO{
		Availability:      string(metric.Availability),
		Grade:             overviewGradeString(metric.Grade),
		UnavailableReason: overviewReasonString(metric.UnavailableReason),
	}
}

func projectOverviewPercentageMetricDTOFromUsecase(metric projectuc.PercentageMetric) projectOverviewPercentageMetricDTO {
	return projectOverviewPercentageMetricDTO{
		Availability:      string(metric.Availability),
		Value:             metric.Value,
		Grade:             overviewGradeString((*projectuc.OverviewGrade)(metric.Grade)),
		UnavailableReason: overviewReasonString(metric.UnavailableReason),
	}
}

func projectOverviewCountMetricDTOFromUsecase(metric projectuc.CountMetric) projectOverviewCountMetricDTO {
	return projectOverviewCountMetricDTO{
		Availability:      string(metric.Availability),
		Value:             metric.Value,
		UnavailableReason: overviewReasonString(metric.UnavailableReason),
	}
}

func overviewGradeString(grade *projectuc.OverviewGrade) *string {
	if grade == nil {
		return nil
	}
	value := string(*grade)
	return &value
}

func overviewReasonString(reason *projectuc.UnavailableReason) *string {
	if reason == nil {
		return nil
	}
	value := string(*reason)
	return &value
}

func overviewGateSourceString(source *projectuc.OverviewGateSource) *string {
	if source == nil {
		return nil
	}
	value := string(*source)
	return &value
}
