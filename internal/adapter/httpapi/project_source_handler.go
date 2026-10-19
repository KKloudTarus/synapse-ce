package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// projectSourcePublicError preserves public error categories without disclosing
// internal execution context identities from guards or repository diagnostics.
func projectSourcePublicError(err error) error {
	var internalOnly interface{ InternalOnly() }
	if errors.As(err, &internalOnly) {
		return err
	}
	for _, category := range []error{shared.ErrForbidden, shared.ErrValidation, shared.ErrNotFound, shared.ErrConflict} {
		if errors.Is(err, category) {
			return fmt.Errorf("%w: Project source request could not be completed; check source access and execution authorization", category)
		}
	}
	return err
}

type projectSourceScanRequest struct {
	Subdirectory string `json:"subdirectory"`
}

func (rt *Router) startProjectSourceScan(w http.ResponseWriter, r *http.Request) {
	var request projectSourceScanRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	job, err := rt.projects.StartSourceScan(r.Context(), PrincipalFrom(r.Context()), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), request.Subdirectory)
	if err != nil {
		writeError(w, rt.log, projectSourcePublicError(err))
		return
	}
	writeJSON(w, http.StatusAccepted, projectSourceScanJob(job))
}

// projectSourceScanJob keeps execution diagnostics inside the operator boundary.
// Worker errors can name the private context or filesystem and are not public DTO fields.
func projectSourceScanJob(job ports.ScanJob) projectAnalysisJobResponse {
	view := projectAnalysisJob(job)
	view.DebugEvents = []ports.ScanDebugEvent{}
	if view.Error != "" {
		view.Error = "Source scan failed. Review source access and execution authorization."
	}
	return view
}

func (rt *Router) getProjectSourceScan(w http.ResponseWriter, r *http.Request) {
	job, err := rt.projects.SourceScanJob(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"), r.PathValue("jobID"))
	if err != nil {
		writeError(w, rt.log, projectSourcePublicError(err))
		return
	}
	writeJSON(w, http.StatusOK, projectSourceScanJob(job))
}

type projectSourceResponseWriter struct{ http.ResponseWriter }

func (w projectSourceResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w projectSourceResponseWriter) sanitizePublicError(err error) error {
	return projectSourcePublicError(err)
}

// withProjectSourceContext resolves the internal analysis engagement by Project
// key and injects it only for existing internal handlers.
func (rt *Router) withProjectSourceContext(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		context, err := rt.projects.SourceContext(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"))
		if err != nil {
			writeError(w, rt.log, projectSourcePublicError(err))
			return
		}
		r.SetPathValue("id", context.Context.ID.String())
		h(projectSourceResponseWriter{w}, r)
	}
}

// sourceFindingResponse retains the established finding JSON shape while
// removing the private context identifier entirely, rather than serializing an
// empty hidden ID for a client to infer a separate resource model from.
func sourceFindingResponse(item finding.Finding) map[string]any {
	raw, _ := json.Marshal(item)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	delete(out, "EngagementID")
	delete(out, "engagement_id")
	return out
}

func (rt *Router) listProjectSourceFindings(w http.ResponseWriter, r *http.Request) {
	context, err := rt.projects.SourceContext(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"))
	if err != nil {
		writeError(w, rt.log, projectSourcePublicError(err))
		return
	}
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil {
			writeError(w, rt.log, projectSourcePublicError(fmt.Errorf("%w: finding page limit is invalid", shared.ErrValidation)))
			return
		}
		limit = parsed
	}
	page, err := rt.findings.ListPage(r.Context(), context.Context.ID, shared.ID(r.URL.Query().Get("after")), limit)
	if err != nil {
		writeError(w, rt.log, projectSourcePublicError(err))
		return
	}
	out := make([]map[string]any, 0, len(page.Items))
	for _, item := range page.Items {
		out = append(out, sourceFindingResponse(item))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "next_cursor": page.NextAfter.String()})
}

func (rt *Router) getProjectSourceFinding(w http.ResponseWriter, r *http.Request) {
	context, err := rt.projects.SourceContext(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"))
	if err != nil {
		writeError(w, rt.log, projectSourcePublicError(err))
		return
	}
	item, err := rt.findings.Get(r.Context(), context.Context.ID, shared.ID(r.PathValue("fid")))
	if err != nil {
		writeError(w, rt.log, projectSourcePublicError(err))
		return
	}
	writeJSON(w, http.StatusOK, sourceFindingResponse(item))
}

func (rt *Router) updateProjectSourceFinding(w http.ResponseWriter, r *http.Request) {
	context, err := rt.projects.SourceContext(r.Context(), shared.ID(TenantFrom(r.Context())), r.PathValue("key"))
	if err != nil {
		writeError(w, rt.log, projectSourcePublicError(err))
		return
	}
	var body struct {
		Status  string `json:"status"`
		Note    string `json:"note"`
		Version int    `json:"version"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return
	}
	updated, err := rt.findings.UpdateStatus(r.Context(), context.Context.ID, shared.ID(r.PathValue("fid")), finding.Status(body.Status), body.Note, PrincipalFrom(r.Context()), body.Version)
	if err != nil {
		writeError(w, rt.log, projectSourcePublicError(err))
		return
	}
	writeJSON(w, http.StatusOK, sourceFindingResponse(updated))
}
