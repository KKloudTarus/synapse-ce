package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/coverage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

type projectService interface {
	Create(context.Context, projectuc.CreateInput) (*project.Project, error)
	CreateFromArchive(context.Context, projectuc.CreateInput, string, io.Reader) (*project.Project, error)
	List(context.Context, shared.ID) ([]*project.Project, error)
	ListSummaries(context.Context, shared.ID) ([]projectuc.ProjectSummary, error)
	Get(context.Context, shared.ID, string) (*project.Project, error)
	AssignGate(context.Context, string, shared.ID, string, string) (*project.Project, error)
	StartAnalysis(context.Context, string, shared.ID, string, *measure.CoverageReport) (ports.ScanJob, error)
	AnalysisStatus(context.Context, shared.ID, string) (ports.ScanJob, error)
	LatestAnalysis(context.Context, shared.ID, string) (projectuc.LatestAnalysis, error)
	Overview(context.Context, shared.ID, string) (projectuc.Overview, error)
	ListAnalyses(context.Context, shared.ID, string, int, time.Time, shared.ID) ([]projectanalysis.Analysis, bool, error)
	GetAnalysis(context.Context, shared.ID, string, string) (projectanalysis.Analysis, error)
	ListHotspots(context.Context, shared.ID, string, hotspot.ListFilter) (hotspot.Page, error)
	GetHotspot(context.Context, shared.ID, string, shared.ID) (hotspot.Hotspot, error)
}

func (rt *Router) SetProjects(s projectService) { rt.projects = s }

type createProjectRequest struct {
	Name                 string                `json:"name"`
	Key                  string                `json:"key"`
	SourceBinding        project.SourceBinding `json:"source_binding"`
	DefaultProfileByLang map[string]string     `json:"default_profile_by_lang"`
	GateID               string                `json:"gate_id"`
}

func (rt *Router) createProject(w http.ResponseWriter, r *http.Request) {
	in := projectuc.CreateInput{TenantID: shared.ID(TenantFrom(r.Context())), CreatedBy: PrincipalFrom(r.Context())}
	var (
		p   *project.Project
		err error
	)
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		// Keep the archive cap at 512 MiB while allowing multipart headers and fields.
		r.Body = http.MaxBytesReader(w, r.Body, (512<<20)+(1<<20))
		if err := r.ParseMultipartForm(8 << 20); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid or oversized archive upload"})
			return
		}
		if r.MultipartForm != nil {
			defer r.MultipartForm.RemoveAll()
		}
		f, h, ferr := r.FormFile("archive")
		if ferr != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "archive file is required"})
			return
		}
		defer f.Close()
		in.Name, in.Key, in.GateID = r.FormValue("name"), r.FormValue("key"), r.FormValue("gate_id")
		p, err = rt.projects.CreateFromArchive(r.Context(), in, h.Filename, f)
	} else {
		var req createProjectRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
			return
		}
		in.Name, in.Key, in.SourceBinding = req.Name, req.Key, req.SourceBinding
		in.DefaultProfileByLang, in.GateID = req.DefaultProfileByLang, req.GateID
		p, err = rt.projects.Create(r.Context(), in)
	}
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

type projectSummaryAnalysisResponse struct {
	ID           string                   `json:"id"`
	CreatedAt    time.Time                `json:"created_at"`
	SourceCommit string                   `json:"source_commit,omitempty"`
	GatePassed   bool                     `json:"gate_passed"`
	GateInfo     projectanalysis.GateInfo `json:"gate_info"`
	Issues       projectanalysis.Counts   `json:"issues"`
	NewIssues    int                      `json:"new_issues"`
	Rating       struct {
		Security        string `json:"security"`
		Reliability     string `json:"reliability"`
		Maintainability string `json:"maintainability"`
	} `json:"rating"`
}

type projectSummaryJobResponse struct {
	ID         string           `json:"id"`
	Status     ports.ScanStatus `json:"status"`
	Stage      string           `json:"stage"`
	Progress   int              `json:"progress"`
	Error      string           `json:"error,omitempty"`
	StartedAt  time.Time        `json:"started_at"`
	FinishedAt *time.Time       `json:"finished_at,omitempty"`
}

type projectSummaryResponse struct {
	ID                   shared.ID                       `json:"ID"`
	TenantID             shared.ID                       `json:"TenantID"`
	Name                 string                          `json:"Name"`
	Key                  string                          `json:"Key"`
	SourceBinding        project.SourceBinding           `json:"SourceBinding"`
	DefaultProfileByLang map[string]string               `json:"DefaultProfileByLang"`
	GateID               string                          `json:"GateID"`
	Audit                shared.Audit                    `json:"Audit"`
	LatestAnalysis       *projectSummaryAnalysisResponse `json:"latest_analysis"`
	LatestJob            *projectSummaryJobResponse      `json:"latest_job"`
}

func (rt *Router) listProjects(w http.ResponseWriter, r *http.Request) {
	list, err := rt.projects.ListSummaries(r.Context(), shared.ID(TenantFrom(r.Context())))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]projectSummaryResponse, len(list))
	for i, summary := range list {
		p := summary.Project
		out[i] = projectSummaryResponse{ID: p.ID, TenantID: p.TenantID, Name: p.Name, Key: p.Key, SourceBinding: p.SourceBinding, DefaultProfileByLang: p.DefaultProfileByLang, GateID: p.GateID, Audit: p.Audit}
		if summary.LatestAnalysis != nil {
			analysis := summary.LatestAnalysis
			out[i].LatestAnalysis = &projectSummaryAnalysisResponse{
				ID: analysis.ID, CreatedAt: analysis.CreatedAt, SourceCommit: analysis.SourceCommit,
				GatePassed: analysis.Gate.Passed, GateInfo: analysis.GateInfo, Issues: analysis.Issues,
				NewIssues: analysis.NewCode.Counts.Total,
				Rating: struct {
					Security        string `json:"security"`
					Reliability     string `json:"reliability"`
					Maintainability string `json:"maintainability"`
				}{Security: string(analysis.Rating.Security), Reliability: string(analysis.Rating.Reliability), Maintainability: string(analysis.Rating.Maintainability)},
			}
		}
		if summary.LatestJob != nil {
			job := summary.LatestJob
			out[i].LatestJob = &projectSummaryJobResponse{ID: job.ID, Status: job.Status, Stage: job.Stage, Progress: job.Progress, Error: job.Error, StartedAt: job.StartedAt, FinishedAt: job.FinishedAt}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (rt *Router) getProject(w http.ResponseWriter, r *http.Request) {
	p, err := rt.projects.Get(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (rt *Router) assignProjectGate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		GateID string `json:"gate_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	p, err := rt.projects.AssignGate(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), body.GateID)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

type projectAnalysisJobResponse struct {
	ID          string                 `json:"id"`
	Target      string                 `json:"target"`
	Kind        string                 `json:"kind"`
	Status      ports.ScanStatus       `json:"status"`
	Stage       string                 `json:"stage"`
	Progress    int                    `json:"progress"`
	Error       string                 `json:"error,omitempty"`
	StartedAt   time.Time              `json:"started_at"`
	FinishedAt  *time.Time             `json:"finished_at,omitempty"`
	DebugEvents []ports.ScanDebugEvent `json:"debug_events"`
}

func projectAnalysisJob(job ports.ScanJob) projectAnalysisJobResponse {
	return projectAnalysisJobResponse{
		ID: job.ID, Target: job.Target, Kind: job.Kind, Status: job.Status,
		Stage: job.Stage, Progress: job.Progress, Error: job.Error,
		StartedAt: job.StartedAt, FinishedAt: job.FinishedAt, DebugEvents: job.DebugEvents,
	}
}

const maxCoverageUploadBytes = 16 << 20

func (rt *Router) startProjectAnalysis(w http.ResponseWriter, r *http.Request) {
	coverage, err := parseCoverageUpload(w, r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	job, err := rt.projects.StartAnalysis(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), coverage)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusAccepted, projectAnalysisJob(job))
}

func parseCoverageUpload(w http.ResponseWriter, r *http.Request) (*measure.CoverageReport, error) {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		return nil, nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxCoverageUploadBytes+(1<<20))
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		return nil, fmt.Errorf("%w: invalid or oversized coverage upload", shared.ErrValidation)
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	file, _, err := r.FormFile("coverage")
	if err != nil {
		return nil, fmt.Errorf("%w: coverage file is required", shared.ErrValidation)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxCoverageUploadBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxCoverageUploadBytes {
		return nil, fmt.Errorf("%w: coverage file is empty or oversized", shared.ErrValidation)
	}
	report, _, err := coverage.ParseBytes(data)
	if err != nil || report.TotalLines == 0 {
		return nil, fmt.Errorf("%w: invalid coverage report", shared.ErrValidation)
	}
	return &report, nil
}

func (rt *Router) projectAnalysisStatus(w http.ResponseWriter, r *http.Request) {
	job, err := rt.projects.AnalysisStatus(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, projectAnalysisJob(job))
}

func (rt *Router) latestProjectAnalysis(w http.ResponseWriter, r *http.Request) {
	latest, err := rt.projects.LatestAnalysis(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	data, err := redactProjectAnalysisEngagementIDs(latest.Result)
	if err != nil {
		writeError(w, rt.log, fmt.Errorf("sanitize project analysis: %w", err))
		return
	}
	var result json.RawMessage = data
	writeJSON(w, http.StatusOK, struct {
		Analysis projectAnalysisResponse `json:"analysis"`
		Result   json.RawMessage         `json:"result"`
	}{Analysis: projectAnalysisDTO(latest.Analysis), Result: result})
}

func redactProjectAnalysisEngagementIDs(data []byte) ([]byte, error) {
	var result map[string]json.RawMessage
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("analysis result must be an object")
	}
	if err := redactFindingEngagementIDs(result, "findings"); err != nil {
		return nil, err
	}
	if raw, ok := result["code_quality"]; ok && !bytes.Equal(raw, []byte("null")) {
		var report map[string]json.RawMessage
		if err := json.Unmarshal(raw, &report); err != nil {
			return nil, fmt.Errorf("decode code_quality: %w", err)
		}
		if report == nil {
			return nil, fmt.Errorf("code_quality must be an object")
		}
		if err := redactFindingEngagementIDs(report, "findings"); err != nil {
			return nil, fmt.Errorf("sanitize code_quality: %w", err)
		}
		encoded, err := json.Marshal(report)
		if err != nil {
			return nil, fmt.Errorf("encode code_quality: %w", err)
		}
		result["code_quality"] = encoded
	}
	return json.Marshal(result)
}

func redactFindingEngagementIDs(object map[string]json.RawMessage, key string) error {
	raw, ok := object[key]
	if !ok || bytes.Equal(raw, []byte("null")) {
		return nil
	}
	var findings []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &findings); err != nil {
		return fmt.Errorf("decode %s: %w", key, err)
	}
	for _, finding := range findings {
		if finding == nil {
			return fmt.Errorf("%s contains a non-object finding", key)
		}
		delete(finding, "EngagementID")
		delete(finding, "engagement_id")
		delete(finding, "engagementId")
	}
	encoded, err := json.Marshal(findings)
	if err != nil {
		return fmt.Errorf("encode %s: %w", key, err)
	}
	object[key] = encoded
	return nil
}
