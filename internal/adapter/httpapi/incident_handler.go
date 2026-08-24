package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/incident"
	"github.com/KKloudTarus/synapse-ce/internal/domain/riskassessment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const incidentMutationBodyCap = 16 << 10

type incidentCommentResponse struct {
	At    time.Time `json:"at"`
	Actor string    `json:"actor"`
	Text  string    `json:"text"`
}

type incidentResponseRefResponse struct {
	ActionID string `json:"action_id"`
	Verified bool   `json:"verified"`
}

type incidentCoverageVectorResponse struct {
	Process   riskassessment.Score `json:"process"`
	Network   riskassessment.Score `json:"network"`
	File      riskassessment.Score `json:"file"`
	Privilege riskassessment.Score `json:"privilege"`
	Reasons   []string             `json:"reasons"`
}

type incidentRiskContextResponse struct {
	Threat   riskassessment.Score `json:"threat"`
	Exposure riskassessment.Score `json:"exposure"`
	Behavior riskassessment.Score `json:"behavior"`
}

type incidentFactorContributionResponse struct {
	Factor string               `json:"factor"`
	Points riskassessment.Score `json:"points"`
	Reason string               `json:"reason"`
}

type incidentRiskResponse struct {
	AssessmentID        string                               `json:"assessment_id"`
	IncidentRevision    int                                  `json:"incident_revision"`
	ScorerVersion       string                               `json:"scorer_version"`
	PolicyVersion       string                               `json:"policy_version"`
	InputSnapshotHash   string                               `json:"input_snapshot_hash"`
	Risk                riskassessment.Score                 `json:"risk"`
	Confidence          riskassessment.Score                 `json:"confidence"`
	Coverage            riskassessment.Score                 `json:"coverage"`
	CoverageVector      incidentCoverageVectorResponse       `json:"coverage_vector"`
	Context             incidentRiskContextResponse          `json:"context"`
	FactorContributions []incidentFactorContributionResponse `json:"factor_contributions"`
	ReasonCodes         []string                             `json:"reason_codes"`
	CreatedAt           time.Time                            `json:"created_at"`
}

type incidentResponse struct {
	ID           string                        `json:"id"`
	AssetID      string                        `json:"asset_id"`
	Title        string                        `json:"title"`
	Severity     shared.Severity               `json:"severity"`
	State        incident.State                `json:"state"`
	Disposition  incident.Disposition          `json:"disposition"`
	OwnerID      string                        `json:"owner_id"`
	DetectionIDs []shared.ID                   `json:"detection_ids"`
	Risk         *incidentRiskResponse         `json:"risk,omitempty"`
	MergedInto   string                        `json:"merged_into,omitempty"`
	Comments     []incidentCommentResponse     `json:"comments"`
	Responses    []incidentResponseRefResponse `json:"responses"`
	Revision     int                           `json:"revision"`
	CreatedAt    time.Time                     `json:"created_at"`
	UpdatedAt    time.Time                     `json:"updated_at"`
}

type incidentEventResponse struct {
	Revision         int                   `json:"revision"`
	Kind             incident.EventKind    `json:"kind"`
	At               time.Time             `json:"at"`
	Actor            string                `json:"actor"`
	AssetID          string                `json:"asset_id,omitempty"`
	Title            string                `json:"title,omitempty"`
	Severity         shared.Severity       `json:"severity,omitempty"`
	DetectionID      string                `json:"detection_id,omitempty"`
	To               incident.State        `json:"to,omitempty"`
	Owner            string                `json:"owner,omitempty"`
	Disposition      incident.Disposition  `json:"disposition,omitempty"`
	Risk             *incidentRiskResponse `json:"risk,omitempty"`
	Comment          string                `json:"comment,omitempty"`
	MergedInto       string                `json:"merged_into,omitempty"`
	ResponseActionID string                `json:"response_action_id,omitempty"`
	Verified         *bool                 `json:"verified,omitempty"`
}

func (rt *Router) listIncidents(w http.ResponseWriter, r *http.Request) {
	assetID, limit, err := incidentListParams(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	items, err := rt.incidents.ListByAsset(r.Context(), assetID, limit)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]incidentResponse, len(items))
	for i, item := range items {
		out[i] = incidentDTO(item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"incidents": out})
}

func (rt *Router) getIncident(w http.ResponseWriter, r *http.Request) {
	id, err := incidentPathID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	item, err := rt.incidents.Get(r.Context(), id)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, incidentDTO(item))
}

func (rt *Router) incidentHistory(w http.ResponseWriter, r *http.Request) {
	id, err := incidentPathID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	events, err := rt.incidents.History(r.Context(), id)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	out := make([]incidentEventResponse, len(events))
	for i, event := range events {
		out[i] = incidentEventDTO(event, i+1)
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out})
}

func (rt *Router) changeIncidentOwner(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Owner            string `json:"owner"`
		ExpectedRevision int    `json:"expected_revision"`
	}
	if !decodeIncidentMutation(w, r, &body) {
		return
	}
	id, err := incidentPathID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if err := rt.requireIncidentRevision(r.Context(), id, body.ExpectedRevision); err != nil {
		writeError(w, rt.log, err)
		return
	}
	updated, err := rt.incidentTriage.AssignOwner(r.Context(), PrincipalFrom(r.Context()), id, strings.TrimSpace(body.Owner))
	writeIncidentMutation(w, rt, updated, err)
}

func (rt *Router) addIncidentComment(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Comment          string `json:"comment"`
		ExpectedRevision int    `json:"expected_revision"`
	}
	if !decodeIncidentMutation(w, r, &body) {
		return
	}
	id, err := incidentPathID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if err := rt.requireIncidentRevision(r.Context(), id, body.ExpectedRevision); err != nil {
		writeError(w, rt.log, err)
		return
	}
	updated, err := rt.incidentTriage.Comment(r.Context(), PrincipalFrom(r.Context()), id, strings.TrimSpace(body.Comment))
	writeIncidentMutation(w, rt, updated, err)
}

func (rt *Router) changeIncidentState(w http.ResponseWriter, r *http.Request) {
	var body struct {
		State            incident.State `json:"state"`
		ExpectedRevision int            `json:"expected_revision"`
	}
	if !decodeIncidentMutation(w, r, &body) {
		return
	}
	id, err := incidentPathID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if err := rt.requireIncidentRevision(r.Context(), id, body.ExpectedRevision); err != nil {
		writeError(w, rt.log, err)
		return
	}
	updated, err := rt.incidentTriage.ChangeStatus(r.Context(), PrincipalFrom(r.Context()), id, body.State)
	writeIncidentMutation(w, rt, updated, err)
}

func (rt *Router) setIncidentDisposition(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Disposition      incident.Disposition `json:"disposition"`
		ExpectedRevision int                  `json:"expected_revision"`
	}
	if !decodeIncidentMutation(w, r, &body) {
		return
	}
	id, err := incidentPathID(r)
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	if err := rt.requireIncidentRevision(r.Context(), id, body.ExpectedRevision); err != nil {
		writeError(w, rt.log, err)
		return
	}
	updated, err := rt.incidentTriage.SetDisposition(r.Context(), PrincipalFrom(r.Context()), id, body.Disposition)
	writeIncidentMutation(w, rt, updated, err)
}

func decodeIncidentMutation(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, incidentMutationBodyCap))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid request body"})
		return false
	}
	return true
}

func writeIncidentMutation(w http.ResponseWriter, rt *Router, updated incident.Incident, err error) {
	if err != nil {
		writeError(w, rt.log, err)
		return
	}
	writeJSON(w, http.StatusOK, incidentDTO(updated))
}

func (rt *Router) requireIncidentRevision(ctx context.Context, id shared.ID, expected int) error {
	if expected < 1 {
		return fmt.Errorf("%w: expected revision must be at least 1", shared.ErrValidation)
	}
	current, err := rt.incidents.Get(ctx, id)
	if err != nil {
		return err
	}
	if current.Revision != expected {
		return fmt.Errorf("%w: incident %s at revision %d, expected %d", shared.ErrConflict, id, current.Revision, expected)
	}
	return nil
}

func incidentPathID(r *http.Request) (shared.ID, error) {
	id := shared.ID(strings.TrimSpace(r.PathValue("id")))
	if id.IsZero() {
		return "", fmt.Errorf("%w: incident id is required", shared.ErrValidation)
	}
	return id, nil
}

func incidentListParams(r *http.Request) (shared.ID, int, error) {
	for key := range r.URL.Query() {
		if key != "asset_id" && key != "limit" {
			return "", 0, fmt.Errorf("%w: unsupported query parameter: %s", shared.ErrValidation, key)
		}
	}
	assetID := shared.ID(strings.TrimSpace(r.URL.Query().Get("asset_id")))
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			return "", 0, fmt.Errorf("%w: limit must be between 1 and 100", shared.ErrValidation)
		}
		limit = parsed
	}
	return assetID, limit, nil
}

func incidentDTO(item incident.Incident) incidentResponse {
	out := incidentResponse{
		ID: item.ID.String(), AssetID: item.AssetID.String(), Title: item.Title, Severity: item.Severity,
		State: item.State, Disposition: item.Disposition, OwnerID: item.OwnerID,
		DetectionIDs: append([]shared.ID{}, item.DetectionIDs...), MergedInto: item.MergedInto.String(),
		Revision: item.Revision, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
		Comments:  make([]incidentCommentResponse, len(item.Comments)),
		Responses: make([]incidentResponseRefResponse, len(item.Responses)),
	}
	for i, comment := range item.Comments {
		out.Comments[i] = incidentCommentResponse{At: comment.At, Actor: comment.Actor, Text: comment.Text}
	}
	for i, response := range item.Responses {
		out.Responses[i] = incidentResponseRefResponse{ActionID: response.ActionID.String(), Verified: response.Verified}
	}
	if item.Risk != nil {
		out.Risk = incidentRiskDTO(*item.Risk)
	}
	return out
}

func incidentEventDTO(event incident.IncidentEvent, revision int) incidentEventResponse {
	out := incidentEventResponse{
		Revision: revision, Kind: event.Kind, At: event.At, Actor: event.Actor,
		AssetID: event.AssetID.String(), Title: event.Title, Severity: event.Severity,
		DetectionID: event.DetectionID.String(), To: event.To, Owner: event.Owner,
		Disposition: event.Disposition, Comment: event.Comment, MergedInto: event.MergedInto.String(),
		ResponseActionID: event.ResponseActionID.String(),
	}
	if event.Risk != nil {
		out.Risk = incidentRiskDTO(*event.Risk)
	}
	if event.Kind == incident.EventResponseVerified {
		verified := event.Verified
		out.Verified = &verified
	}
	return out
}

func incidentRiskDTO(risk riskassessment.RiskAssessment) *incidentRiskResponse {
	out := &incidentRiskResponse{
		AssessmentID: risk.AssessmentID.String(), IncidentRevision: risk.IncidentRevision,
		ScorerVersion: risk.ScorerVersion, PolicyVersion: risk.PolicyVersion,
		InputSnapshotHash: risk.InputSnapshotHash, Risk: risk.Risk, Confidence: risk.Confidence,
		Coverage: risk.Coverage,
		CoverageVector: incidentCoverageVectorResponse{
			Process: risk.CoverageVector.Process, Network: risk.CoverageVector.Network,
			File: risk.CoverageVector.File, Privilege: risk.CoverageVector.Privilege,
			Reasons: append([]string{}, risk.CoverageVector.Reasons...),
		},
		Context:             incidentRiskContextResponse{Threat: risk.Context.Threat, Exposure: risk.Context.Exposure, Behavior: risk.Context.Behavior},
		FactorContributions: make([]incidentFactorContributionResponse, len(risk.FactorContributions)),
		ReasonCodes:         append([]string{}, risk.ReasonCodes...), CreatedAt: risk.CreatedAt,
	}
	for i, factor := range risk.FactorContributions {
		out.FactorContributions[i] = incidentFactorContributionResponse{Factor: factor.Factor, Points: factor.Points, Reason: factor.Reason}
	}
	return out
}
