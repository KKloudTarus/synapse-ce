package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	snapshotuc "github.com/KKloudTarus/synapse-ce/internal/usecase/assessmentsnapshot"
)

const assessmentSnapshotRequestLimit = int64(64 << 10)

type finalizeAssessmentSnapshotRequest struct {
	SelectedRuns []finalizeAssessmentSnapshotRun `json:"selected_runs"`
}

type finalizeAssessmentSnapshotRun struct {
	RunID    string   `json:"run_id"`
	LaneKeys []string `json:"lane_keys,omitempty"`
}

type assessmentSnapshotResponse struct {
	ID             shared.ID             `json:"id"`
	CycleID        shared.ID             `json:"cycle_id"`
	AssessmentID   shared.ID             `json:"assessment_id"`
	SnapshotNumber int                   `json:"snapshot_number"`
	Lifecycle      domain.Lifecycle      `json:"lifecycle"`
	Provenance     domain.Provenance     `json:"provenance"`
	Boundary       domain.Boundary       `json:"boundary"`
	RunReferences  []domain.RunReference `json:"run_references"`
	Dimensions     []domain.Dimension    `json:"dimensions"`
	SchemaVersion  int                   `json:"schema_version"`
	ContentHash    string                `json:"content_hash"`
	CreatedAt      time.Time             `json:"created_at"`
	CreatedBy      string                `json:"created_by"`
	FinalizedAt    *time.Time            `json:"finalized_at"`
	FinalizedBy    string                `json:"finalized_by"`
	SupersededAt   *time.Time            `json:"superseded_at,omitempty"`
	SupersededBy   string                `json:"superseded_by,omitempty"`
}

type finalizedAssessmentSnapshotResponse struct {
	Snapshot       assessmentSnapshotResponse `json:"snapshot"`
	DefaultVersion int64                      `json:"default_version"`
}

type assessmentSnapshotListResponse struct {
	Items             []assessmentSnapshotResponse `json:"items"`
	DefaultSnapshotID shared.ID                    `json:"default_snapshot_id,omitempty"`
	DefaultVersion    int64                        `json:"default_version"`
}

func (rt *Router) finalizeAssessmentSnapshot(w http.ResponseWriter, r *http.Request) {
	requestKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if requestKey == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "idempotency_key_required"})
		return
	}
	if strings.TrimSpace(r.Header.Get("If-Match")) == "" {
		writeJSON(w, http.StatusPreconditionRequired, errorBody{Error: "precondition_required"})
		return
	}
	expectedVersion, err := parseSnapshotIfMatch(r.Header.Get("If-Match"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_if_match"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, assessmentSnapshotRequestLimit)
	var request finalizeAssessmentSnapshotRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		var sizeErr *http.MaxBytesError
		if errors.As(err, &sizeErr) {
			writeJSON(w, http.StatusRequestEntityTooLarge, errorBody{Error: "request_too_large"})
			return
		}
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_request"})
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_request"})
		return
	}
	selectedRuns := make([]snapshotuc.RunSelection, len(request.SelectedRuns))
	for index, selected := range request.SelectedRuns {
		selectedRuns[index] = snapshotuc.RunSelection{RunID: selected.RunID, LaneKeys: selected.LaneKeys}
	}
	snapshot, created, err := rt.assessmentSnapshots.Finalize(r.Context(), snapshotuc.FinalizeInput{
		TenantID: shared.ID(TenantFrom(r.Context())), AssessmentID: shared.ID(r.PathValue("id")), SelectedRuns: selectedRuns,
		RequestKey: requestKey, ExpectedDefaultVersion: expectedVersion, Actor: PrincipalFrom(r.Context()),
	})
	if err != nil {
		writeAssessmentSnapshotError(w, rt.log, err)
		return
	}
	if !created {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	w.Header().Set("ETag", snapshotETag(snapshot.DefaultVersion))
	writeJSON(w, http.StatusCreated, finalizedAssessmentSnapshotResponse{Snapshot: newAssessmentSnapshotResponse(snapshot), DefaultVersion: snapshot.DefaultVersion})
}

func (rt *Router) listAssessmentSnapshots(w http.ResponseWriter, r *http.Request) {
	tenantID := shared.ID(TenantFrom(r.Context()))
	assessmentID := shared.ID(r.PathValue("id"))
	snapshots, err := rt.assessmentSnapshots.ListByAssessment(r.Context(), tenantID, assessmentID)
	if err != nil {
		writeAssessmentSnapshotError(w, rt.log, err)
		return
	}
	response := assessmentSnapshotListResponse{Items: make([]assessmentSnapshotResponse, 0, len(snapshots))}
	for index := range snapshots {
		response.Items = append(response.Items, newAssessmentSnapshotResponse(&snapshots[index]))
	}
	if len(snapshots) > 0 {
		_, pointer, err := rt.assessmentSnapshots.GetDefault(r.Context(), tenantID, assessmentID)
		if err != nil && !errors.Is(err, shared.ErrNotFound) {
			writeAssessmentSnapshotError(w, rt.log, err)
			return
		}
		if err == nil {
			response.DefaultSnapshotID, response.DefaultVersion = pointer.SnapshotID, pointer.Version
		}
	}
	w.Header().Set("ETag", snapshotETag(response.DefaultVersion))
	writeJSON(w, http.StatusOK, response)
}

func (rt *Router) getAssessmentSnapshot(w http.ResponseWriter, r *http.Request) {
	snapshot, err := rt.assessmentSnapshots.Get(r.Context(), shared.ID(TenantFrom(r.Context())), shared.ID(r.PathValue("snapshotId")))
	if err != nil {
		writeAssessmentSnapshotError(w, rt.log, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf("\"sha256:%s\"", snapshot.ContentHash))
	writeJSON(w, http.StatusOK, newAssessmentSnapshotResponse(snapshot))
}

func parseSnapshotIfMatch(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "W/") {
		value = strings.TrimSpace(strings.TrimPrefix(value, "W/"))
	}
	value = strings.Trim(value, "\"")
	version, err := strconv.ParseInt(value, 10, 64)
	if err != nil || version < 0 {
		return 0, errors.New("invalid If-Match")
	}
	return version, nil
}

func snapshotETag(version int64) string { return fmt.Sprintf("\"%d\"", version) }

func newAssessmentSnapshotResponse(snapshot *domain.Snapshot) assessmentSnapshotResponse {
	return assessmentSnapshotResponse{
		ID: snapshot.ID, CycleID: snapshot.CycleID, AssessmentID: snapshot.AssessmentID, SnapshotNumber: snapshot.SnapshotNumber,
		Lifecycle: snapshot.Lifecycle, Provenance: snapshot.Provenance, Boundary: snapshot.Boundary,
		RunReferences: snapshot.RunReferences, Dimensions: snapshot.Dimensions, SchemaVersion: snapshot.SchemaVersion,
		ContentHash: snapshot.ContentHash, CreatedAt: snapshot.CreatedAt, CreatedBy: snapshot.CreatedBy,
		FinalizedAt: snapshot.FinalizedAt, FinalizedBy: snapshot.FinalizedBy, SupersededAt: snapshot.SupersededAt, SupersededBy: snapshot.SupersededBy,
	}
}

func writeAssessmentSnapshotError(w http.ResponseWriter, log *slog.Logger, err error) {
	status, code := http.StatusInternalServerError, "internal_error"
	switch {
	case errors.Is(err, snapshotuc.ErrIdempotencyBodyMismatch):
		status, code = http.StatusConflict, "idempotency_body_mismatch"
	case errors.Is(err, shared.ErrValidation):
		status, code = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, shared.ErrConflict):
		status, code = http.StatusConflict, "snapshot_conflict"
	case errors.Is(err, shared.ErrNotFound):
		status, code = http.StatusNotFound, "not_found"
	case errors.Is(err, shared.ErrForbidden):
		status, code = http.StatusForbidden, "forbidden"
	default:
		requestLogger(w, log).Error("assessment snapshot request failed", "err", err)
	}
	writeJSON(w, status, errorBody{Error: code})
}
