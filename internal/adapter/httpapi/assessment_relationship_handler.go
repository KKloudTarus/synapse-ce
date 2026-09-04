package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentrelationship"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	relationshipuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentrelationship"
)

const assessmentRelationshipBodyLimit = int64(16 << 10)

type generateAssessmentRelationshipRequest struct {
	PredecessorCycleID    string `json:"predecessor_cycle_id"`
	SuccessorCycleID      string `json:"successor_cycle_id"`
	ImportedReferenceHash string `json:"imported_reference_hash,omitempty"`
	ExpiresInDays         int    `json:"expires_in_days,omitempty"`
}

func (rt *Router) generateAssessmentRelationshipCandidate(w http.ResponseWriter, r *http.Request) {
	var request generateAssessmentRelationshipRequest
	if !decodeAssessmentRelationshipJSON(w, r, &request) {
		return
	}
	view, created, err := rt.assessmentRelationships.Generate(r.Context(), relationshipuc.GenerateInput{
		TenantID: shared.ID(TenantFrom(r.Context())), PredecessorCycleID: shared.ID(request.PredecessorCycleID),
		SuccessorCycleID: shared.ID(request.SuccessorCycleID), ImportedReferenceHash: request.ImportedReferenceHash,
		ExpiresIn: time.Duration(request.ExpiresInDays) * 24 * time.Hour, Actor: PrincipalFrom(r.Context()),
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.Header().Set("ETag", relationshipETag(view.Version))
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, view)
}

func (rt *Router) listAssessmentRelationshipCandidates(w http.ResponseWriter, r *http.Request) {
	limit := 0
	if value := strings.TrimSpace(r.URL.Query().Get("limit")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_limit"})
			return
		}
		limit = parsed
	}
	views, err := rt.assessmentRelationships.List(r.Context(), shared.ID(TenantFrom(r.Context())), r.URL.Query().Get("status"), limit)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views})
}

func (rt *Router) getAssessmentRelationshipCandidate(w http.ResponseWriter, r *http.Request) {
	view, err := rt.assessmentRelationships.Get(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("candidateId")))
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	w.Header().Set("ETag", relationshipETag(view.Version))
	writeJSON(w, http.StatusOK, view)
}

type decideAssessmentRelationshipRequest struct {
	Action domain.DecisionAction `json:"action"`
	Reason string                `json:"reason"`
}

func (rt *Router) decideAssessmentRelationshipCandidate(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(r.Header.Get("If-Match")) == "" {
		writeJSON(w, http.StatusPreconditionRequired, errorBody{Error: "precondition_required"})
		return
	}
	expectedVersion, err := parseCycleIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		writeJSON(w, http.StatusPreconditionRequired, errorBody{Error: "precondition_required"})
		return
	}
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "idempotency_key_required"})
		return
	}
	var request decideAssessmentRelationshipRequest
	if !decodeAssessmentRelationshipJSON(w, r, &request) {
		return
	}
	view, replayed, err := rt.assessmentRelationships.Decide(r.Context(), relationshipuc.DecideInput{
		TenantID: shared.ID(TenantFrom(r.Context())), CandidateID: shared.ID(r.PathValue("candidateId")),
		ExpectedVersion: expectedVersion, IdempotencyKey: key, Action: request.Action,
		Reason: request.Reason, Actor: PrincipalFrom(r.Context()),
	})
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	w.Header().Set("ETag", relationshipETag(view.Version))
	writeJSON(w, http.StatusOK, view)
}

func decodeAssessmentRelationshipJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, assessmentRelationshipBodyLimit)
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

func relationshipETag(version int64) string { return fmt.Sprintf("\"%d\"", version) }
