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

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

type projectService interface {
	Create(context.Context, projectuc.CreateInput) (*project.Project, error)
	CreateFromArchive(context.Context, projectuc.CreateInput, string, io.Reader) (*project.Project, error)
	List(context.Context, shared.ID) ([]*project.Project, error)
	Get(context.Context, shared.ID, string) (*project.Project, error)
	StartAnalysis(context.Context, string, shared.ID, string) (ports.ScanJob, error)
	AnalysisStatus(context.Context, shared.ID, string) (ports.ScanJob, error)
	LatestAnalysis(context.Context, shared.ID, string) ([]byte, error)
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
		in.Name, in.Key = r.FormValue("name"), r.FormValue("key")
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

func (rt *Router) listProjects(w http.ResponseWriter, r *http.Request) {
	list, err := rt.projects.List(r.Context(), shared.ID(TenantFrom(r.Context())))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (rt *Router) getProject(w http.ResponseWriter, r *http.Request) {
	p, err := rt.projects.Get(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"))
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

func (rt *Router) startProjectAnalysis(w http.ResponseWriter, r *http.Request) {
	job, err := rt.projects.StartAnalysis(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())), r.PathValue("key"))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusAccepted, projectAnalysisJob(job))
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
	data, err := rt.projects.LatestAnalysis(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	data, err = redactProjectAnalysisEngagementIDs(data)
	if err != nil {
		writeError(w, rt.log, fmt.Errorf("sanitize project analysis: %w", err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
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
