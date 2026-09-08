package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	comparisonuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentcomparison"
)

const assessmentComparisonBodyLimit = int64(16 << 10)

type createAssessmentComparisonRequest struct {
	BaselineSnapshotID string      `json:"baseline_snapshot_id"`
	CurrentSnapshotID  string      `json:"current_snapshot_id"`
	Mode               domain.Mode `json:"mode"`
}

func (rt *Router) createAssessmentComparison(w http.ResponseWriter, r *http.Request) {
	var request createAssessmentComparisonRequest
	if !decodeAssessmentComparisonJSON(w, r, &request) {
		return
	}
	response, err := rt.assessmentComparisons.QueueRetained(r.Context(), comparisonuc.RetainedRequest{
		TenantID: shared.ID(TenantFrom(r.Context())), Actor: PrincipalFrom(r.Context()), Route: "POST /api/v1/assessment-comparisons", IdempotencyKey: r.Header.Get("Idempotency-Key"),
	}, comparisonuc.QueueInput{
		BaselineSnapshotID: shared.ID(request.BaselineSnapshotID), CurrentSnapshotID: shared.ID(request.CurrentSnapshotID), Mode: request.Mode,
		FingerprintVersion: 1, RiskModelVersion: comparisonuc.RiskModelVersionV1,
	})
	if err != nil {
		writeAssessmentComparisonError(w, err)
		return
	}
	writeAssessmentComparisonRetained(w, response)
}

func (rt *Router) getAssessmentComparison(w http.ResponseWriter, r *http.Request) {
	view, err := rt.assessmentComparisons.Get(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("comparisonId")))
	if err != nil {
		writeAssessmentComparisonError(w, err)
		return
	}
	w.Header().Set("ETag", relationshipETag(view.Version))
	writeJSON(w, http.StatusOK, view)
}

func (rt *Router) listAssessmentComparisonItems(w http.ResponseWriter, r *http.Request) {
	limit := 0
	if value := strings.TrimSpace(r.URL.Query().Get("limit")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_limit"})
			return
		}
		limit = parsed
	}
	page, err := rt.assessmentComparisons.ListItems(r.Context(), comparisonuc.ListItemsInput{
		TenantID: shared.ID(TenantFrom(r.Context())), ComparisonID: shared.ID(r.PathValue("comparisonId")), Cursor: r.URL.Query().Get("cursor"), Limit: limit,
		Presence: strings.TrimSpace(r.URL.Query().Get("presence")), ChangeFlag: domain.ChangeFlag(strings.TrimSpace(r.URL.Query().Get("change_flag"))),
		Severity: shared.Severity(strings.TrimSpace(r.URL.Query().Get("severity"))), ProducerKind: r.URL.Query().Get("producer"), FindingKind: r.URL.Query().Get("finding_kind"),
		Disposition: strings.TrimSpace(r.URL.Query().Get("disposition")), ReviewState: strings.TrimSpace(r.URL.Query().Get("review_state")),
	})
	if err != nil {
		writeAssessmentComparisonError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

type reviewAssessmentComparisonItemRequest struct {
	CandidateID         string `json:"candidate_id"`
	SourceObservationID string `json:"source_observation_id"`
	TargetObservationID string `json:"target_observation_id,omitempty"`
	Reason              string `json:"reason"`
}

func (rt *Router) confirmAssessmentComparisonItem(w http.ResponseWriter, r *http.Request) {
	rt.reviewAssessmentComparisonItem(w, r, comparisonuc.ReviewConfirm)
}

func (rt *Router) unlinkAssessmentComparisonItem(w http.ResponseWriter, r *http.Request) {
	rt.reviewAssessmentComparisonItem(w, r, comparisonuc.ReviewUnlink)
}

func (rt *Router) reviewAssessmentComparisonItem(w http.ResponseWriter, r *http.Request, action comparisonuc.ReviewAction) {
	if strings.TrimSpace(r.Header.Get("If-Match")) == "" {
		writeJSON(w, http.StatusPreconditionRequired, errorBody{Error: "precondition_required"})
		return
	}
	expectedVersion, err := parseCycleIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_if_match"})
		return
	}
	var request reviewAssessmentComparisonItemRequest
	if !decodeAssessmentComparisonJSON(w, r, &request) {
		return
	}
	response, err := rt.assessmentComparisons.Review(r.Context(), comparisonuc.ReviewInput{
		Request: comparisonuc.RetainedRequest{
			TenantID: shared.ID(TenantFrom(r.Context())), Actor: PrincipalFrom(r.Context()), Route: "POST /api/v1/assessment-comparisons/{comparisonId}/items/{itemId}/" + string(action), IdempotencyKey: r.Header.Get("Idempotency-Key"),
		},
		ComparisonID: shared.ID(r.PathValue("comparisonId")), ItemID: shared.ID(r.PathValue("itemId")), CandidateID: shared.ID(request.CandidateID),
		SourceObservationID: shared.ID(request.SourceObservationID), TargetObservationID: shared.ID(request.TargetObservationID), ExpectedVersion: expectedVersion,
		Action: action, Reason: request.Reason,
	})
	if err != nil {
		writeAssessmentComparisonError(w, err)
		return
	}
	writeAssessmentComparisonRetained(w, response)
}

func decodeAssessmentComparisonJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, assessmentComparisonBodyLimit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, errorBody{Error: "request_too_large"})
		} else {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_request"})
		}
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_request"})
		return false
	}
	return true
}

func writeAssessmentComparisonRetained(w http.ResponseWriter, response comparisonuc.RetainedResponse) {
	if response.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(response.Body)
}

func writeAssessmentComparisonError(w http.ResponseWriter, err error) {
	code := comparisonuc.ErrorCode(err)
	if code == "" {
		code = "assessment_comparison_error"
	}
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, shared.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, shared.ErrForbidden):
		status = http.StatusForbidden
	case errors.Is(err, shared.ErrConflict):
		status = http.StatusConflict
	case errors.Is(err, shared.ErrValidation):
		status = http.StatusBadRequest
	}
	switch code {
	case domain.ReasonLifecycleReverse, domain.ReasonLifecycleSibling, domain.ReasonLifecycleDirectionAvailable,
		domain.ReasonSameSnapshot, domain.ReasonCrossCycle, domain.ReasonSnapshotNotFinalized, domain.ReasonMissingRelationship:
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, errorBody{Error: code})
}
