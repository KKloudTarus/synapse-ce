package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	cmpdom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	cycledom "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	engdom "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	cycleuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcycle"
)

const assessmentCycleRequestLimit = int64(1 << 20)

type createAssessmentRetestRequest struct {
	Name                    string      `json:"name"`
	PredecessorAssessmentID string      `json:"predecessor_assessment_id"`
	ScopeStrategy           string      `json:"scope_strategy"`
	ProfileStrategy         string      `json:"profile_strategy"`
	AuthorizedFrom          string      `json:"authorized_from"`
	AuthorizedTo            string      `json:"authorized_to"`
	Timezone                string      `json:"timezone"`
	RoE                     *engdom.RoE `json:"roe"`
}

type assessmentRelationshipChangeRequest struct {
	Command                    string `json:"command"`
	AssessmentID               string `json:"assessment_id"`
	NewPredecessorAssessmentID string `json:"new_predecessor_assessment_id"`
	SelectedHeadAssessmentID   string `json:"selected_head_assessment_id"`
	PreviewToken               string `json:"preview_token"`
	Reason                     string `json:"reason"`
}

type assessmentClosureRequest struct {
	PreviewToken       string   `json:"preview_token"`
	Reason             string   `json:"reason"`
	OverrideBlockerIDs []string `json:"override_blocker_ids"`
	OverrideReason     string   `json:"override_reason"`
}

type assessmentReopenRequest struct {
	PreviewToken string `json:"preview_token"`
	Reason       string `json:"reason"`
}

func (rt *Router) createAssessmentRetest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, assessmentCycleRequestLimit)
	var request createAssessmentRetestRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_request"})
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_request"})
		return
	}
	authorizedFrom, err := parseRFC3339Ptr(request.AuthorizedFrom)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_authorized_from"})
		return
	}
	authorizedTo, err := parseRFC3339Ptr(request.AuthorizedTo)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_authorized_to"})
		return
	}
	response, err := rt.assessmentCycles.CreateRetestAssessment(r.Context(), cycleuc.CreateRetestAssessmentInput{
		Request: cycleuc.RetainedRequest{
			TenantID: shared.ID(TenantFrom(r.Context())), Actor: PrincipalFrom(r.Context()), Route: r.URL.Path,
			IdempotencyKey: r.Header.Get("Idempotency-Key"),
		},
		AssessmentID: shared.ID(r.PathValue("assessmentId")), Name: request.Name,
		PredecessorAssessmentID: shared.ID(request.PredecessorAssessmentID), ScopeStrategy: request.ScopeStrategy,
		ProfileStrategy: request.ProfileStrategy, AuthorizedFrom: authorizedFrom, AuthorizedTo: authorizedTo,
		Timezone: request.Timezone, RoE: request.RoE,
	})
	if err != nil {
		writeAssessmentCycleError(w, rt.log, err)
		return
	}
	writeRetainedJSON(w, response)
}

func (rt *Router) getAssessmentLifecycle(w http.ResponseWriter, r *http.Request) {
	response, err := rt.assessmentCycles.GetLifecycle(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("assessmentId")))
	if err != nil {
		writeAssessmentCycleError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (rt *Router) getAssessmentCycle(w http.ResponseWriter, r *http.Request) {
	response, err := rt.assessmentCycles.GetCycle(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("cycleId")))
	if err != nil {
		writeAssessmentCycleError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (rt *Router) listAssessmentCycles(w http.ResponseWriter, r *http.Request) {
	limit := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: cycleuc.CodeInvalidPageSize})
			return
		}
		limit = parsed
	}
	response, err := rt.assessmentCycles.ListCycles(r.Context(), cycleuc.ListCyclesInput{
		TenantID: shared.ID(TenantFrom(r.Context())), Status: cycledom.Status(r.URL.Query().Get("status")),
		BoundaryKind: cycledom.BoundaryKind(r.URL.Query().Get("boundary_kind")), AssessmentStatus: engdom.Status(r.URL.Query().Get("assessment_status")),
		SelectedHeadID: shared.ID(r.URL.Query().Get("selected_head_assessment_id")), AssessmentType: cycledom.AssessmentType(r.URL.Query().Get("assessment_type")),
		ProducerKind: r.URL.Query().Get("producer"), FindingKind: r.URL.Query().Get("finding_kind"), ReviewState: r.URL.Query().Get("review_state"),
		ChangePresence: cmpdom.Presence(r.URL.Query().Get("change_presence")), ChangeSeverity: shared.Severity(r.URL.Query().Get("change_severity")),
		ScanStaleness: r.URL.Query().Get("scan_staleness"), Search: r.URL.Query().Get("q"), Cursor: r.URL.Query().Get("cursor"), Limit: limit,
	})
	if err != nil {
		writeAssessmentCycleError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (rt *Router) listAssessmentCycleMembers(w http.ResponseWriter, r *http.Request) {
	limit := 0
	if value := strings.TrimSpace(r.URL.Query().Get("limit")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: cycleuc.CodeInvalidPageSize})
			return
		}
		limit = parsed
	}
	page, err := rt.assessmentCycles.ListCycleMembers(r.Context(), cycleuc.ListCycleMembersInput{
		TenantID: shared.ID(TenantFrom(r.Context())), CycleID: shared.ID(r.PathValue("cycleId")), Cursor: r.URL.Query().Get("cursor"), Limit: limit,
	})
	if err != nil {
		writeAssessmentCycleError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (rt *Router) archiveAssessmentCycle(w http.ResponseWriter, r *http.Request) {
	expectedVersion, err := parseCycleIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		writeJSON(w, http.StatusPreconditionRequired, errorBody{Error: "precondition_required"})
		return
	}
	response, err := rt.assessmentCycles.ArchiveCycle(r.Context(), cycleuc.ArchiveCycleRequest{
		Request: cycleuc.RetainedRequest{
			TenantID: shared.ID(TenantFrom(r.Context())), Actor: PrincipalFrom(r.Context()), Route: r.URL.Path,
			IdempotencyKey: r.Header.Get("Idempotency-Key"),
		},
		CycleID: shared.ID(r.PathValue("cycleId")), ExpectedVersion: expectedVersion,
	})
	if err != nil {
		writeAssessmentCycleError(w, rt.log, err)
		return
	}
	writeRetainedJSON(w, response)
}

func (rt *Router) previewAssessmentRelationshipChange(w http.ResponseWriter, r *http.Request) {
	var request assessmentRelationshipChangeRequest
	if !decodeAssessmentCycleJSON(w, r, &request) {
		return
	}
	preview, err := rt.assessmentCycles.PreviewRelationshipChange(r.Context(), cycleuc.RelationshipPreviewInput{
		TenantID: shared.ID(TenantFrom(r.Context())), Actor: PrincipalFrom(r.Context()), CycleID: shared.ID(r.PathValue("cycleId")),
		Request: cycleuc.RelationshipChangeRequest{Command: request.Command, AssessmentID: shared.ID(request.AssessmentID), NewPredecessorAssessmentID: shared.ID(request.NewPredecessorAssessmentID), SelectedHeadAssessmentID: shared.ID(request.SelectedHeadAssessmentID)},
	})
	if err != nil {
		writeAssessmentCycleError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (rt *Router) commitAssessmentRelationshipChange(w http.ResponseWriter, r *http.Request) {
	expectedVersion, err := parseCycleIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		writeJSON(w, http.StatusPreconditionRequired, errorBody{Error: "precondition_required"})
		return
	}
	var request assessmentRelationshipChangeRequest
	if !decodeAssessmentCycleJSON(w, r, &request) {
		return
	}
	response, err := rt.assessmentCycles.CommitRelationshipChange(r.Context(), cycleuc.RelationshipCommitInput{
		Request: cycleuc.RetainedRequest{TenantID: shared.ID(TenantFrom(r.Context())), Actor: PrincipalFrom(r.Context()), Route: r.URL.Path, IdempotencyKey: r.Header.Get("Idempotency-Key")},
		CycleID: shared.ID(r.PathValue("cycleId")), ExpectedVersion: expectedVersion, PreviewToken: request.PreviewToken, Reason: request.Reason,
		Change: cycleuc.RelationshipChangeRequest{Command: request.Command, AssessmentID: shared.ID(request.AssessmentID), NewPredecessorAssessmentID: shared.ID(request.NewPredecessorAssessmentID), SelectedHeadAssessmentID: shared.ID(request.SelectedHeadAssessmentID)},
	})
	if err != nil {
		writeAssessmentCycleError(w, rt.log, err)
		return
	}
	writeRetainedJSON(w, response)
}

func (rt *Router) previewAssessmentClosure(w http.ResponseWriter, r *http.Request) {
	var request assessmentClosureRequest
	if !decodeAssessmentCycleJSON(w, r, &request) {
		return
	}
	preview, err := rt.assessmentCycles.PreviewClosure(r.Context(), cycleuc.ClosurePreviewInput{
		TenantID: shared.ID(TenantFrom(r.Context())), Actor: PrincipalFrom(r.Context()), CycleID: shared.ID(r.PathValue("cycleId")),
		Reason: request.Reason, OverrideBlockerIDs: request.OverrideBlockerIDs, OverrideReason: request.OverrideReason,
	})
	if err != nil {
		writeAssessmentCycleError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (rt *Router) commitAssessmentClosure(w http.ResponseWriter, r *http.Request) {
	expectedVersion, err := parseCycleIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		writeJSON(w, http.StatusPreconditionRequired, errorBody{Error: "precondition_required"})
		return
	}
	var request assessmentClosureRequest
	if !decodeAssessmentCycleJSON(w, r, &request) {
		return
	}
	response, err := rt.assessmentCycles.CommitClosure(r.Context(), cycleuc.ClosureCommitInput{
		Request: cycleuc.RetainedRequest{TenantID: shared.ID(TenantFrom(r.Context())), Actor: PrincipalFrom(r.Context()), Route: r.URL.Path, IdempotencyKey: r.Header.Get("Idempotency-Key")},
		CycleID: shared.ID(r.PathValue("cycleId")), ExpectedVersion: expectedVersion, PreviewToken: request.PreviewToken,
		Reason: request.Reason, OverrideBlockerIDs: request.OverrideBlockerIDs, OverrideReason: request.OverrideReason,
	})
	if err != nil {
		writeAssessmentCycleError(w, rt.log, err)
		return
	}
	writeRetainedJSON(w, response)
}

func (rt *Router) previewAssessmentReopen(w http.ResponseWriter, r *http.Request) {
	var request struct{}
	if !decodeAssessmentCycleJSON(w, r, &request) {
		return
	}
	preview, err := rt.assessmentCycles.PreviewReopen(r.Context(), cycleuc.ReopenPreviewInput{
		TenantID: shared.ID(TenantFrom(r.Context())), Actor: PrincipalFrom(r.Context()), CycleID: shared.ID(r.PathValue("cycleId")),
	})
	if err != nil {
		writeAssessmentCycleError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (rt *Router) commitAssessmentReopen(w http.ResponseWriter, r *http.Request) {
	expectedVersion, err := parseCycleIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		writeJSON(w, http.StatusPreconditionRequired, errorBody{Error: "precondition_required"})
		return
	}
	var request assessmentReopenRequest
	if !decodeAssessmentCycleJSON(w, r, &request) {
		return
	}
	response, err := rt.assessmentCycles.CommitReopen(r.Context(), cycleuc.ReopenCommitInput{
		Request: cycleuc.RetainedRequest{TenantID: shared.ID(TenantFrom(r.Context())), Actor: PrincipalFrom(r.Context()), Route: r.URL.Path, IdempotencyKey: r.Header.Get("Idempotency-Key")},
		CycleID: shared.ID(r.PathValue("cycleId")), ExpectedVersion: expectedVersion, PreviewToken: request.PreviewToken, Reason: request.Reason,
	})
	if err != nil {
		writeAssessmentCycleError(w, rt.log, err)
		return
	}
	writeRetainedJSON(w, response)
}

func (rt *Router) listAssessmentClosureManifests(w http.ResponseWriter, r *http.Request) {
	manifests, err := rt.assessmentCycles.ListClosureManifests(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("cycleId")))
	if err != nil {
		writeAssessmentCycleError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": manifests})
}

func (rt *Router) getAssessmentClosureManifest(w http.ResponseWriter, r *http.Request) {
	manifest, err := rt.assessmentCycles.GetClosureManifest(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("cycleId")), shared.ID(r.PathValue("manifestId")))
	if err != nil {
		writeAssessmentCycleError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, manifest)
}

func (rt *Router) downloadAssessmentClosureReport(w http.ResponseWriter, r *http.Request) {
	report, err := rt.assessmentCycles.GetClosureReport(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("cycleId")), shared.ID(r.PathValue("manifestId")))
	if err != nil {
		writeAssessmentCycleError(w, rt.log, err)
		return
	}
	etag := `"sha256:` + report.ContentHash + `"`
	w.Header().Set("Cache-Control", "private, max-age=31536000, immutable")
	w.Header().Set("Content-Disposition", `attachment; filename="assessment-cycle-closure-report.json"`)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", etag)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(report.Content)
}

func decodeAssessmentCycleJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, assessmentCycleRequestLimit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_request"})
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_request"})
		return false
	}
	return true
}

func parseCycleIfMatch(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "W/") {
		value = strings.TrimSpace(strings.TrimPrefix(value, "W/"))
	}
	value = strings.Trim(value, "\"")
	version, err := strconv.ParseInt(value, 10, 64)
	if err != nil || version < 1 {
		return 0, errors.New("invalid If-Match")
	}
	return version, nil
}

func writeRetainedJSON(w http.ResponseWriter, response cycleuc.RetainedResponse) {
	w.Header().Set("Content-Type", "application/json")
	if response.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, bytes.NewReader(response.Body))
}

func writeAssessmentCycleError(w http.ResponseWriter, log *slog.Logger, err error) {
	code := cycleuc.ErrorCode(err)
	if code == "" {
		writeError(w, log, err)
		return
	}
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, shared.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, shared.ErrForbidden):
		status = http.StatusForbidden
	case errors.Is(err, shared.ErrConflict):
		status = http.StatusConflict
	}
	writeJSON(w, status, errorBody{Error: code})
}
