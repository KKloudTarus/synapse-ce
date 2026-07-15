package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	projectuc "github.com/KKloudTarus/synapse-ce/internal/usecase/projectuc"
)

type projectService interface {
	Create(context.Context, projectuc.CreateInput) (*project.Project, error)
	List(context.Context, shared.ID) ([]*project.Project, error)
	Get(context.Context, shared.ID, string) (*project.Project, error)
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
	var req createProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid json body"})
		return
	}
	p, err := rt.projects.Create(r.Context(), projectuc.CreateInput{
		TenantID: shared.ID(TenantFrom(r.Context())), CreatedBy: PrincipalFrom(r.Context()),
		Name: req.Name, Key: req.Key, SourceBinding: req.SourceBinding,
		DefaultProfileByLang: req.DefaultProfileByLang, GateID: req.GateID,
	})
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
