package assessmentcomparison

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcomparison"
	lineagedom "github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	lineageuc "github.com/KKloudTarus/synapse-ce/internal/usecase/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	JobKind                        = "assessment_comparison_generate"
	CodeIdempotencyKeyRequired     = "idempotency_key_required"
	CodeIdempotencyBodyMismatch    = "idempotency_body_mismatch"
	CodeIdempotencyRequestPending  = "idempotency_request_in_progress"
	CodeComparisonVersionConflict  = "comparison_version_conflict"
	CodeReviewCandidateMismatch    = "review_candidate_mismatch"
	CodeReviewSourceMissing        = "review_source_observation_missing"
	CodeReviewReasonRejected       = "review_reason_rejected"
	DefaultAssessmentItemPageLimit = 100
	MaxAssessmentItemPageLimit     = 200
)

type APIError struct {
	Code  string
	Cause error
}

func (err *APIError) Error() string { return err.Code }
func (err *APIError) Unwrap() error { return err.Cause }

func ErrorCode(err error) string {
	var coded *APIError
	if errors.As(err, &coded) {
		return coded.Code
	}
	return ""
}

type RetainedRequest struct {
	TenantID       shared.ID
	Actor          string
	Route          string
	IdempotencyKey string
}

type RetainedResponse struct {
	StatusCode int
	Body       []byte
	Replayed   bool
}

type Job struct {
	ComparisonID shared.ID `json:"comparison_id"`
}

type ComparisonView struct {
	ID                    shared.ID      `json:"id"`
	CycleID               shared.ID      `json:"cycle_id"`
	BaselineSnapshotID    shared.ID      `json:"baseline_snapshot_id"`
	CurrentSnapshotID     shared.ID      `json:"current_snapshot_id"`
	Mode                  domain.Mode    `json:"mode"`
	InputHash             string         `json:"input_hash"`
	AlgorithmVersion      int            `json:"algorithm_version"`
	FingerprintVersion    int            `json:"fingerprint_version"`
	RiskModelVersion      int            `json:"risk_model_version"`
	CoveragePolicyVersion int            `json:"coverage_policy_version"`
	Status                domain.Status  `json:"status"`
	Version               int64          `json:"version"`
	Attempts              int            `json:"attempts"`
	FailureCode           string         `json:"failure_code,omitempty"`
	ContentHash           string         `json:"content_hash,omitempty"`
	Summary               domain.Summary `json:"summary"`
	CreatedAt             time.Time      `json:"created_at"`
	UpdatedAt             time.Time      `json:"updated_at"`
	CompletedAt           *time.Time     `json:"completed_at,omitempty"`
	SupersededAt          *time.Time     `json:"superseded_at,omitempty"`
	SupersededBy          shared.ID      `json:"superseded_by,omitempty"`
}

type QueueResult struct {
	Comparison ComparisonView `json:"comparison"`
	Created    bool           `json:"created"`
}

type ItemPage struct {
	Items      []domain.Item `json:"items"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

type ListItemsInput struct {
	TenantID     shared.ID
	ComparisonID shared.ID
	Cursor       string
	Limit        int
	Presence     string
	ChangeFlag   domain.ChangeFlag
	Severity     shared.Severity
	ProducerKind string
	FindingKind  string
	Disposition  string
	ReviewState  string
}

type ReviewAction string

const (
	ReviewConfirm ReviewAction = "confirm"
	ReviewUnlink  ReviewAction = "unlink"
)

type ReviewInput struct {
	Request             RetainedRequest
	ComparisonID        shared.ID
	ItemID              shared.ID
	CandidateID         shared.ID
	SourceObservationID shared.ID
	TargetObservationID shared.ID
	ExpectedVersion     int64
	Action              ReviewAction
	Reason              string
}

type ReviewResult struct {
	OverrideEventID         shared.ID     `json:"override_event_id"`
	SupersededComparisonID  shared.ID     `json:"superseded_comparison_id"`
	ReplacementComparisonID shared.ID     `json:"replacement_comparison_id"`
	ReplacementStatus       domain.Status `json:"replacement_status"`
}

func (service *Service) QueueRetained(ctx context.Context, request RetainedRequest, input QueueInput) (RetainedResponse, error) {
	input.TenantID, input.Actor = request.TenantID, request.Actor
	canonical := struct {
		BaselineSnapshotID shared.ID   `json:"baseline_snapshot_id"`
		CurrentSnapshotID  shared.ID   `json:"current_snapshot_id"`
		Mode               domain.Mode `json:"mode"`
		FingerprintVersion int         `json:"fingerprint_version"`
		RiskModelVersion   int         `json:"risk_model_version"`
	}{input.BaselineSnapshotID, input.CurrentSnapshotID, input.Mode, input.FingerprintVersion, input.RiskModelVersion}
	return service.executeRetained(ctx, request, canonical, func(txCtx context.Context) (int, any, error) {
		comparison, created, decision, err := service.Queue(txCtx, input)
		if err != nil {
			return 0, nil, err
		}
		if !decision.Allowed {
			return 0, nil, &APIError{Code: decision.ReasonCode, Cause: shared.ErrValidation}
		}
		status := 200
		if created && !isTerminal(comparison.Status) {
			status = 202
		}
		return status, QueueResult{Comparison: projectComparison(comparison), Created: created}, nil
	})
}

func (service *Service) Get(ctx context.Context, tenantID, comparisonID shared.ID) (ComparisonView, error) {
	comparison, err := service.comparisons.GetMetadata(ctx, shared.TenantOrDefault(tenantID), comparisonID)
	if err != nil {
		return ComparisonView{}, err
	}
	return projectComparison(comparison), nil
}

func (service *Service) ListItems(ctx context.Context, input ListItemsInput) (ItemPage, error) {
	input.TenantID = shared.TenantOrDefault(input.TenantID)
	if input.ComparisonID.IsZero() {
		return ItemPage{}, fmt.Errorf("%w: comparison id is required", shared.ErrValidation)
	}
	if input.Limit == 0 {
		input.Limit = DefaultAssessmentItemPageLimit
	}
	input.ProducerKind, input.FindingKind = strings.TrimSpace(input.ProducerKind), strings.TrimSpace(input.FindingKind)
	if input.Limit < 1 || input.Limit > MaxAssessmentItemPageLimit || input.ChangeFlag != "" && !input.ChangeFlag.Valid() || !validPresenceFilter(input.Presence) ||
		input.Severity != "" && !input.Severity.Valid() || !validItemTokenFilter(input.ProducerKind) || !validItemTokenFilter(input.FindingKind) ||
		input.Disposition != "" && input.Disposition != "current_actionable" && input.Disposition != "baseline_only" && input.Disposition != "non_actionable" ||
		input.ReviewState != "" && input.ReviewState != "needs_review" && input.ReviewState != "verified" && input.ReviewState != "clear" {
		return ItemPage{}, fmt.Errorf("%w: comparison item filter is invalid", shared.ErrValidation)
	}
	after, err := decodeItemCursor(input.Cursor)
	if err != nil {
		return ItemPage{}, &APIError{Code: "invalid_cursor", Cause: shared.ErrValidation}
	}
	page, err := service.comparisons.ListItems(ctx, input.TenantID, input.ComparisonID, ports.AssessmentComparisonItemFilter{
		AfterPosition: after, Limit: input.Limit, Presence: input.Presence, ChangeFlag: input.ChangeFlag, Severity: input.Severity,
		ProducerKind: input.ProducerKind, FindingKind: input.FindingKind, Disposition: input.Disposition, ReviewState: input.ReviewState,
	})
	if err != nil {
		return ItemPage{}, err
	}
	result := ItemPage{Items: page.Items}
	if page.HasMore {
		result.NextCursor = encodeItemCursor(page.NextPosition)
	}
	return result, nil
}

func (service *Service) Review(ctx context.Context, input ReviewInput) (RetainedResponse, error) {
	if service.reviewer == nil {
		return RetainedResponse{}, fmt.Errorf("%w: comparison review workflow is unavailable", shared.ErrValidation)
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if input.ComparisonID.IsZero() || input.ItemID.IsZero() || input.CandidateID.IsZero() || input.SourceObservationID.IsZero() || input.ExpectedVersion <= 0 || input.Action != ReviewConfirm && input.Action != ReviewUnlink {
		return RetainedResponse{}, fmt.Errorf("%w: comparison review input is invalid", shared.ErrValidation)
	}
	if !safeReviewReason(input.Reason) {
		return RetainedResponse{}, &APIError{Code: CodeReviewReasonRejected, Cause: shared.ErrValidation}
	}
	canonical := struct {
		ComparisonID        shared.ID    `json:"comparison_id"`
		ItemID              shared.ID    `json:"item_id"`
		CandidateID         shared.ID    `json:"candidate_id"`
		SourceObservationID shared.ID    `json:"source_observation_id"`
		TargetObservationID shared.ID    `json:"target_observation_id,omitempty"`
		ExpectedVersion     int64        `json:"expected_version"`
		Action              ReviewAction `json:"action"`
		Reason              string       `json:"reason"`
	}{input.ComparisonID, input.ItemID, input.CandidateID, input.SourceObservationID, input.TargetObservationID, input.ExpectedVersion, input.Action, input.Reason}
	return service.executeRetained(ctx, input.Request, canonical, func(txCtx context.Context) (int, any, error) {
		comparison, err := service.comparisons.Get(txCtx, input.Request.TenantID, input.ComparisonID)
		if err != nil {
			return 0, nil, err
		}
		if comparison.Version != input.ExpectedVersion {
			return 0, nil, &APIError{Code: CodeComparisonVersionConflict, Cause: shared.ErrConflict}
		}
		item, err := service.comparisons.GetItem(txCtx, input.Request.TenantID, input.ComparisonID, input.ItemID)
		if err != nil {
			return 0, nil, err
		}
		if item.Presence != domain.PresenceNeedsReview && item.NeutralPresence != domain.NeutralNeedsReview || !containsID(item.ReviewCandidateIDs, input.CandidateID) {
			return 0, nil, &APIError{Code: CodeReviewCandidateMismatch, Cause: shared.ErrConflict}
		}
		candidate, err := service.lineage.GetCandidate(txCtx, input.Request.TenantID, comparison.CycleID, input.CandidateID)
		if err != nil {
			return 0, nil, err
		}
		source, err := service.lineage.GetObservation(txCtx, input.Request.TenantID, comparison.CycleID, input.SourceObservationID)
		if err != nil || !candidateContainsObservation(candidate, input.SourceObservationID) {
			return 0, nil, &APIError{Code: CodeReviewSourceMissing, Cause: shared.ErrValidation}
		}
		if !candidateContainsIdentity(candidate, item.IdentityID) {
			return 0, nil, &APIError{Code: CodeReviewCandidateMismatch, Cause: shared.ErrConflict}
		}
		var targetObservationID shared.ID
		if !input.TargetObservationID.IsZero() {
			target, targetErr := service.lineage.GetObservation(txCtx, input.Request.TenantID, comparison.CycleID, input.TargetObservationID)
			if targetErr != nil || target.IdentityID != item.IdentityID || !candidateContainsObservation(candidate, input.TargetObservationID) {
				return 0, nil, &APIError{Code: CodeReviewCandidateMismatch, Cause: shared.ErrValidation}
			}
			targetObservationID = target.ID
		}
		action, overrideAction := lineagedom.ResolutionConfirmExisting, lineagedom.OverrideConfirm
		if input.Action == ReviewUnlink {
			action, overrideAction = lineagedom.ResolutionUnlink, lineagedom.OverrideUnlink
		}
		afterRefs := reviewedRefs(candidate.Refs, item.IdentityID, input.Action)
		_, _, _, err = service.reviewer.ResolveCandidate(txCtx, lineageuc.ResolveInput{
			TenantID: input.Request.TenantID, CycleID: comparison.CycleID, CandidateID: candidate.ID, EventID: service.ids.NewID(),
			Action: action, Actor: input.Request.Actor, Reason: input.Reason, AfterRefs: afterRefs, ExpectedVersion: candidate.Version,
		})
		if err != nil {
			return 0, nil, err
		}
		expectedOverrideVersion, priorOverrideID := int64(0), shared.ID("")
		active, activeErr := service.lineage.GetActiveOverride(txCtx, input.Request.TenantID, comparison.CycleID, source.ID)
		if activeErr == nil {
			expectedOverrideVersion, priorOverrideID = active.Version, active.ID
		} else if !errors.Is(activeErr, shared.ErrNotFound) {
			return 0, nil, activeErr
		}
		override, _, err := service.reviewer.AppendOverride(txCtx, lineageuc.OverrideInput{
			TenantID: input.Request.TenantID, CycleID: comparison.CycleID, EventID: service.ids.NewID(), Action: overrideAction,
			SourceObservationID: source.ID, SourceIdentityID: source.IdentityID, TargetObservationID: targetObservationID, TargetIdentityID: item.IdentityID,
			Actor: input.Request.Actor, Reason: input.Reason, ExpectedVersion: expectedOverrideVersion, PriorEventID: priorOverrideID,
		})
		if err != nil {
			return 0, nil, err
		}
		replacement, _, err := service.Replace(txCtx, ReplaceInput{TenantID: input.Request.TenantID, ComparisonID: comparison.ID, Actor: input.Request.Actor})
		if err != nil {
			return 0, nil, err
		}
		status := 202
		if isTerminal(replacement.Status) {
			status = 200
		}
		return status, ReviewResult{OverrideEventID: override.ID, SupersededComparisonID: comparison.ID, ReplacementComparisonID: replacement.ID, ReplacementStatus: replacement.Status}, nil
	})
}

func (service *Service) HandleJob(ctx context.Context, payload []byte) error {
	job, err := decodeComparisonJob(payload)
	if err != nil {
		return err
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	_, err = service.Generate(ctx, WorkInput{TenantID: tenantID, ComparisonID: job.ComparisonID, Actor: "system:assessment-comparison-worker"})
	return err
}

func (service *Service) OnDeadLetter(ctx context.Context, payload []byte) error {
	job, err := decodeComparisonJob(payload)
	if err != nil {
		return err
	}
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return fmt.Errorf("%w: tenant context is required", shared.ErrValidation)
	}
	defer service.observeBacklog(context.WithoutCancel(ctx), tenantID)
	return service.transactions.Run(ctx, tenantID, func(txCtx context.Context) error {
		comparison, err := service.comparisons.Get(txCtx, tenantID, job.ComparisonID)
		if err != nil || isTerminal(comparison.Status) || comparison.Status == domain.StatusFailed {
			return err
		}
		if comparison.Status == domain.StatusQueued {
			expected := comparison.Version
			if err := comparison.Start(expected, service.clock.Now().UTC()); err != nil {
				return err
			}
			if err := service.comparisons.UpdateCAS(txCtx, comparison, expected); err != nil {
				return err
			}
		}
		expected := comparison.Version
		if err := comparison.Fail("dead_lettered", false, DefaultMaxAttempts, expected, service.clock.Now().UTC()); err != nil {
			return err
		}
		if err := service.comparisons.UpdateCAS(txCtx, comparison, expected); err != nil {
			return err
		}
		return service.recordAudit(txCtx, "system:assessment-comparison-worker", "assessment_comparison.dead_lettered", comparison, nil)
	})
}

func (service *Service) executeRetained(ctx context.Context, request RetainedRequest, canonical any, operation func(context.Context) (int, any, error)) (RetainedResponse, error) {
	if service.requests == nil {
		return RetainedResponse{}, fmt.Errorf("%w: assessment comparison request store is unavailable", shared.ErrValidation)
	}
	scope := ports.AssessmentCycleRequestScope{TenantID: shared.TenantOrDefault(request.TenantID), Actor: strings.TrimSpace(request.Actor), Route: strings.TrimSpace(request.Route), IdempotencyKey: strings.TrimSpace(request.IdempotencyKey)}
	if scope.Actor == "" || scope.Route == "" {
		return RetainedResponse{}, fmt.Errorf("%w: actor and route are required", shared.ErrValidation)
	}
	if scope.IdempotencyKey == "" || len(scope.IdempotencyKey) > 128 {
		return RetainedResponse{}, &APIError{Code: CodeIdempotencyKeyRequired, Cause: shared.ErrValidation}
	}
	requestHash, err := comparisonCanonicalHash(canonical)
	if err != nil {
		return RetainedResponse{}, err
	}
	var response RetainedResponse
	createdReservation := false
	err = service.transactions.Run(ctx, scope.TenantID, func(txCtx context.Context) error {
		stored, created, err := service.requests.BeginAssessmentCycleRequest(txCtx, ports.AssessmentCycleRequest{Scope: scope, RequestHash: requestHash, CreatedAt: service.clock.Now().UTC()})
		if err != nil {
			return err
		}
		createdReservation = created
		if !created {
			if stored.RequestHash != requestHash {
				return &APIError{Code: CodeIdempotencyBodyMismatch, Cause: shared.ErrConflict}
			}
			if stored.CompletedAt == nil || stored.StatusCode == 0 || len(stored.ResponseBody) == 0 {
				return &APIError{Code: CodeIdempotencyRequestPending, Cause: shared.ErrConflict}
			}
			response = RetainedResponse{StatusCode: stored.StatusCode, Body: append([]byte(nil), stored.ResponseBody...), Replayed: true}
			return nil
		}
		statusCode, value, err := operation(txCtx)
		if err != nil {
			return err
		}
		body, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if err := service.requests.CompleteAssessmentCycleRequest(txCtx, scope, requestHash, statusCode, body, service.clock.Now().UTC()); err != nil {
			return err
		}
		response = RetainedResponse{StatusCode: statusCode, Body: body}
		return nil
	})
	if err != nil && createdReservation {
		_ = service.requests.AbortAssessmentCycleRequest(context.WithoutCancel(ctx), scope, requestHash)
	}
	return response, err
}

func projectComparison(comparison domain.Comparison) ComparisonView {
	return ComparisonView{
		ID: comparison.ID, CycleID: comparison.CycleID, BaselineSnapshotID: comparison.BaselineSnapshotID, CurrentSnapshotID: comparison.CurrentSnapshotID,
		Mode: comparison.Mode, InputHash: comparison.InputHash, AlgorithmVersion: comparison.AlgorithmVersion, FingerprintVersion: comparison.FingerprintVersion,
		RiskModelVersion: comparison.RiskModelVersion, CoveragePolicyVersion: comparison.CoveragePolicyVersion, Status: comparison.Status, Version: comparison.Version,
		Attempts: comparison.Attempts, FailureCode: comparison.FailureCode, ContentHash: comparison.ContentHash, Summary: comparison.Summary,
		CreatedAt: comparison.CreatedAt, UpdatedAt: comparison.UpdatedAt, CompletedAt: comparison.CompletedAt, SupersededAt: comparison.SupersededAt, SupersededBy: comparison.SupersededBy,
	}
}

func reviewedRefs(refs []lineagedom.CandidateRef, targetIdentityID shared.ID, action ReviewAction) []lineagedom.CandidateRef {
	result := append([]lineagedom.CandidateRef(nil), refs...)
	for index := range result {
		result[index].ReasonPayload = cloneReasonPayload(result[index].ReasonPayload)
		if !result[index].IdentityID.IsZero() {
			result[index].Role = lineagedom.RoleExcluded
			if action == ReviewConfirm && result[index].IdentityID == targetIdentityID {
				result[index].Role = lineagedom.RoleSelected
			}
		}
	}
	return result
}

func cloneReasonPayload(input map[string]string) map[string]string {
	if input == nil {
		return map[string]string{}
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func candidateContainsIdentity(candidate lineagedom.MatchCandidate, identityID shared.ID) bool {
	for _, reference := range candidate.Refs {
		if reference.IdentityID == identityID {
			return true
		}
	}
	return false
}

func candidateContainsObservation(candidate lineagedom.MatchCandidate, observationID shared.ID) bool {
	for _, reference := range candidate.Refs {
		if reference.ObservationID == observationID {
			return true
		}
	}
	return false
}

func containsID(values []shared.ID, target shared.ID) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func safeReviewReason(reason string) bool {
	if reason == "" || len(reason) > 512 {
		return false
	}
	lower := strings.ToLower(reason)
	for _, marker := range []string{"password=", "passwd=", "api_key", "apikey", "access_token", "authorization:", "bearer ", "private_key", "client_secret"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}

func validPresenceFilter(value string) bool {
	if value == "" {
		return true
	}
	return domain.Presence(value).Valid() || domain.NeutralPresence(value).Valid()
}

func validItemTokenFilter(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 256 || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if char < 32 || char == 127 {
			return false
		}
	}
	return true
}

func comparisonCanonicalHash(value any) (string, error) {
	// ponytail: request schemas contain no maps or floats; use RFC 8785 if either is introduced.
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	digest := sha256.Sum256(bytes.TrimSuffix(buffer.Bytes(), []byte("\n")))
	return hex.EncodeToString(digest[:]), nil
}

func encodeItemCursor(position int) string {
	payload, _ := json.Marshal(struct {
		Position int `json:"position"`
	}{position})
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeItemCursor(cursor string) (int, error) {
	if strings.TrimSpace(cursor) == "" {
		return -1, nil
	}
	if len(cursor) > 128 {
		return 0, fmt.Errorf("invalid cursor")
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || len(raw) > 64 {
		return 0, fmt.Errorf("invalid cursor")
	}
	var value struct {
		Position int `json:"position"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || value.Position < 0 {
		return 0, fmt.Errorf("invalid cursor")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return 0, fmt.Errorf("invalid cursor")
	}
	return value.Position, nil
}

func decodeComparisonJob(payload []byte) (Job, error) {
	if len(payload) == 0 || len(payload) > 4096 {
		return Job{}, fmt.Errorf("%w: comparison job payload is invalid", shared.ErrValidation)
	}
	var job Job
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&job); err != nil || job.ComparisonID.IsZero() {
		return Job{}, fmt.Errorf("%w: comparison job payload is invalid", shared.ErrValidation)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Job{}, fmt.Errorf("%w: comparison job payload is invalid", shared.ErrValidation)
	}
	return job, nil
}
