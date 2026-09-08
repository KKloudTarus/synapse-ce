package assessmentcomparison

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type Status string

const (
	StatusQueued      Status = "queued"
	StatusGenerating  Status = "generating"
	StatusComplete    Status = "complete"
	StatusNeedsReview Status = "needs_review"
	StatusFailed      Status = "failed"
	StatusSuperseded  Status = "superseded"
)

func (status Status) Valid() bool {
	switch status {
	case StatusQueued, StatusGenerating, StatusComplete, StatusNeedsReview, StatusFailed, StatusSuperseded:
		return true
	}
	return false
}

type Comparison struct {
	TenantID              shared.ID
	CycleID               shared.ID
	ID                    shared.ID
	BaselineSnapshotID    shared.ID
	CurrentSnapshotID     shared.ID
	Mode                  Mode
	InputHash             string
	InputPayload          []byte
	AlgorithmVersion      int
	FingerprintVersion    int
	RiskModelVersion      int
	CoveragePolicyVersion int
	Status                Status
	Version               int64
	Attempts              int
	FailureCode           string
	ContentHash           string
	Items                 []Item
	Summary               Summary
	CreatedAt             time.Time
	UpdatedAt             time.Time
	CompletedAt           *time.Time
	SupersededAt          *time.Time
	SupersededBy          shared.ID
}

func NewQueued(tenantID, cycleID, id shared.ID, input GenerationInput, payload []byte, inputHash string, now time.Time) (Comparison, error) {
	comparison := Comparison{
		TenantID: tenantID, CycleID: cycleID, ID: id,
		BaselineSnapshotID: input.Baseline.ID, CurrentSnapshotID: input.Current.ID, Mode: input.Mode,
		InputHash: inputHash, InputPayload: append([]byte(nil), payload...),
		AlgorithmVersion: input.AlgorithmVersion, FingerprintVersion: input.FingerprintVersion,
		RiskModelVersion: input.RiskModelVersion, CoveragePolicyVersion: input.CoveragePolicyVersion,
		Status: StatusQueued, Version: 1, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}
	return comparison, comparison.Validate()
}

func (comparison Comparison) Validate() error {
	if comparison.TenantID.IsZero() || comparison.CycleID.IsZero() || comparison.ID.IsZero() || comparison.BaselineSnapshotID.IsZero() || comparison.CurrentSnapshotID.IsZero() {
		return fmt.Errorf("%w: comparison ownership and snapshots are required", shared.ErrValidation)
	}
	if comparison.BaselineSnapshotID == comparison.CurrentSnapshotID || !comparison.Mode.Valid() || !validDigest(comparison.InputHash) || len(comparison.InputPayload) == 0 || len(comparison.InputPayload) > 64*1024 {
		return fmt.Errorf("%w: comparison input is invalid", shared.ErrValidation)
	}
	if comparison.AlgorithmVersion <= 0 || comparison.FingerprintVersion <= 0 || comparison.RiskModelVersion <= 0 || comparison.CoveragePolicyVersion <= 0 || !comparison.Status.Valid() || comparison.Version <= 0 || comparison.Attempts < 0 {
		return fmt.Errorf("%w: comparison versions or lifecycle are invalid", shared.ErrValidation)
	}
	if comparison.CreatedAt.IsZero() || comparison.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: comparison timestamps are required", shared.ErrValidation)
	}
	switch comparison.Status {
	case StatusQueued, StatusGenerating:
		if comparison.ContentHash != "" || len(comparison.Items) != 0 || comparison.CompletedAt != nil || comparison.SupersededAt != nil || !comparison.SupersededBy.IsZero() {
			return fmt.Errorf("%w: active comparison has terminal output", shared.ErrValidation)
		}
	case StatusComplete, StatusNeedsReview:
		if !validDigest(comparison.ContentHash) || comparison.CompletedAt == nil || comparison.SupersededAt != nil || !comparison.SupersededBy.IsZero() {
			return fmt.Errorf("%w: completed comparison metadata is invalid", shared.ErrValidation)
		}
	case StatusFailed:
		if !validReason(comparison.FailureCode) || comparison.ContentHash != "" || comparison.CompletedAt != nil || comparison.SupersededAt != nil || !comparison.SupersededBy.IsZero() {
			return fmt.Errorf("%w: failed comparison metadata is invalid", shared.ErrValidation)
		}
	case StatusSuperseded:
		if !validDigest(comparison.ContentHash) || comparison.CompletedAt == nil || comparison.SupersededAt == nil || comparison.SupersededBy.IsZero() {
			return fmt.Errorf("%w: superseded comparison metadata is invalid", shared.ErrValidation)
		}
	}
	return validateItems(comparison.Mode, comparison.Items)
}

func (comparison *Comparison) Start(expectedVersion int64, now time.Time) error {
	if comparison == nil || expectedVersion != comparison.Version {
		return fmt.Errorf("%w: comparison version mismatch", shared.ErrConflict)
	}
	if comparison.Status != StatusQueued && comparison.Status != StatusFailed {
		return fmt.Errorf("%w: comparison cannot start from %s", shared.ErrValidation, comparison.Status)
	}
	comparison.Status, comparison.FailureCode = StatusGenerating, ""
	comparison.Attempts++
	comparison.Version++
	comparison.UpdatedAt = now.UTC()
	return comparison.Validate()
}

func (comparison *Comparison) Complete(items []Item, expectedVersion int64, now time.Time) error {
	if comparison == nil || expectedVersion != comparison.Version {
		return fmt.Errorf("%w: comparison version mismatch", shared.ErrConflict)
	}
	if comparison.Status != StatusGenerating {
		return fmt.Errorf("%w: comparison is not generating", shared.ErrValidation)
	}
	items = append([]Item(nil), items...)
	sort.Slice(items, func(i, j int) bool { return items[i].IdentityID < items[j].IdentityID })
	for index := range items {
		items[index].Position = index
		items[index].ID = comparisonItemID(comparison.ID, items[index].IdentityID)
		items[index].ReviewCandidateIDs = canonicalItemIDs(items[index].ReviewCandidateIDs)
		items[index].ReviewCandidates = canonicalReviewCandidates(items[index].ReviewCandidates)
		items[index].MatchMethods = canonicalMatchMethods(items[index].MatchMethods)
	}
	if err := validateItems(comparison.Mode, items); err != nil {
		return err
	}
	status := StatusComplete
	for _, item := range items {
		if item.Presence == PresenceNeedsReview || item.NeutralPresence == NeutralNeedsReview {
			status = StatusNeedsReview
			break
		}
	}
	summary := Summarize(items)
	summary.ComparisonID = comparison.ID
	summary.BaselineSnapshotID = comparison.BaselineSnapshotID
	summary.CurrentSnapshotID = comparison.CurrentSnapshotID
	summary.RiskModelVersion = comparison.RiskModelVersion
	hash, err := hashOutput(comparison, items, summary)
	if err != nil {
		return err
	}
	completedAt := now.UTC()
	comparison.Status, comparison.Items, comparison.Summary, comparison.ContentHash = status, items, summary, hash
	comparison.CompletedAt, comparison.UpdatedAt = &completedAt, completedAt
	comparison.Version++
	return comparison.Validate()
}

func (comparison *Comparison) Fail(code string, retryable bool, maxAttempts int, expectedVersion int64, now time.Time) error {
	if comparison == nil || expectedVersion != comparison.Version {
		return fmt.Errorf("%w: comparison version mismatch", shared.ErrConflict)
	}
	if comparison.Status != StatusGenerating || !validReason(code) || maxAttempts <= 0 {
		return fmt.Errorf("%w: comparison failure transition is invalid", shared.ErrValidation)
	}
	comparison.Status = StatusFailed
	if retryable && comparison.Attempts < maxAttempts {
		comparison.Status = StatusQueued
	}
	comparison.FailureCode = code
	comparison.Version++
	comparison.UpdatedAt = now.UTC()
	if comparison.Status == StatusQueued {
		comparison.FailureCode = ""
	}
	return comparison.Validate()
}

func (comparison *Comparison) Supersede(successorID shared.ID, expectedVersion int64, now time.Time) error {
	if comparison == nil || expectedVersion != comparison.Version {
		return fmt.Errorf("%w: comparison version mismatch", shared.ErrConflict)
	}
	if comparison.Status != StatusComplete && comparison.Status != StatusNeedsReview || successorID.IsZero() || successorID == comparison.ID {
		return fmt.Errorf("%w: comparison supersession is invalid", shared.ErrValidation)
	}
	supersededAt := now.UTC()
	comparison.Status, comparison.SupersededAt, comparison.SupersededBy = StatusSuperseded, &supersededAt, successorID
	comparison.Version++
	comparison.UpdatedAt = supersededAt
	return comparison.Validate()
}

func validateItems(mode Mode, items []Item) error {
	seenItems := map[shared.ID]struct{}{}
	seenIdentities := map[shared.ID]struct{}{}
	for position, item := range items {
		if item.ID.IsZero() || item.Position != position || item.IdentityID.IsZero() || item.BaselineRiskMilli < 0 || item.CurrentRiskMilli < 0 || item.BaselineObservationID.IsZero() && item.CurrentObservationID.IsZero() {
			return fmt.Errorf("%w: comparison item is invalid", shared.ErrValidation)
		}
		if _, duplicate := seenItems[item.ID]; duplicate {
			return fmt.Errorf("%w: comparison contains duplicate item %q", shared.ErrValidation, item.ID)
		}
		seenItems[item.ID] = struct{}{}
		if _, duplicate := seenIdentities[item.IdentityID]; duplicate {
			return fmt.Errorf("%w: comparison contains duplicate identity %q", shared.ErrValidation, item.IdentityID)
		}
		seenIdentities[item.IdentityID] = struct{}{}
		if mode == ModeLifecycle && (!item.Presence.Valid() || item.NeutralPresence != "") ||
			mode == ModeNeutral && (!item.NeutralPresence.Valid() || item.Presence != "" || item.FixedBasis != "") {
			return fmt.Errorf("%w: comparison item presence does not match mode", shared.ErrValidation)
		}
		if item.FixedBasis != "" && !item.FixedBasis.Valid() || item.FixedBasis == FixedByComparableAbsence && item.Presence != PresenceNotDetected ||
			item.FixedBasis == FixedByExplicitVerification && (item.VerificationID.IsZero() || item.VerificationState == "") {
			return fmt.Errorf("%w: comparison item fixed basis is invalid", shared.ErrValidation)
		}
		if item.VerificationState != "" && !validReason(item.VerificationState) || (item.VerificationState == "") != item.VerificationID.IsZero() {
			return fmt.Errorf("%w: comparison item verification is invalid", shared.ErrValidation)
		}
		if err := validateItemProjection(item); err != nil {
			return err
		}
		seenFlags := map[ChangeFlag]struct{}{}
		for _, flag := range item.ChangeFlags {
			if !flag.Valid() {
				return fmt.Errorf("%w: comparison change flag is invalid", shared.ErrValidation)
			}
			if _, duplicate := seenFlags[flag]; duplicate {
				return fmt.Errorf("%w: comparison change flag is duplicated", shared.ErrValidation)
			}
			seenFlags[flag] = struct{}{}
		}
		if !equalItemIDs(item.ReviewCandidateIDs, canonicalItemIDs(item.ReviewCandidateIDs)) {
			return fmt.Errorf("%w: comparison review candidate ids are invalid", shared.ErrValidation)
		}
		if !equalReviewCandidates(item.ReviewCandidates, canonicalReviewCandidates(item.ReviewCandidates)) {
			return fmt.Errorf("%w: comparison review candidates are invalid", shared.ErrValidation)
		}
		for _, candidate := range item.ReviewCandidates {
			if !containsItemID(item.ReviewCandidateIDs, candidate.ID) {
				return fmt.Errorf("%w: comparison review candidate metadata is unreferenced", shared.ErrValidation)
			}
		}
		if !equalMatchMethods(item.MatchMethods, canonicalMatchMethods(item.MatchMethods)) {
			return fmt.Errorf("%w: comparison match methods are invalid", shared.ErrValidation)
		}
	}
	return nil
}

func validateItemProjection(item Item) error {
	legacy := item.ProducerKind == "" && item.FindingKind == "" && item.TargetCanonical == ""
	if legacy {
		if item.CoverageDecision != "" && item.CoverageDecision != assessmentsnapshot.NotComparable {
			return fmt.Errorf("%w: legacy comparison coverage is invalid", shared.ErrValidation)
		}
		return nil
	}
	if strings.TrimSpace(item.ProducerKind) != item.ProducerKind || strings.TrimSpace(item.FindingKind) != item.FindingKind || strings.TrimSpace(item.TargetCanonical) != item.TargetCanonical || item.ProducerKind == "" || item.FindingKind == "" || item.TargetCanonical == "" {
		return fmt.Errorf("%w: comparison item identity projection is invalid", shared.ErrValidation)
	}
	if !validComparability(item.CoverageDecision) || !validObservationView(item.BaselineObservationID, item.BaselineObservation) || !validObservationView(item.CurrentObservationID, item.CurrentObservation) {
		return fmt.Errorf("%w: comparison item observation projection is invalid", shared.ErrValidation)
	}
	return nil
}

func validObservationView(observationID shared.ID, view ObservationView) bool {
	if observationID.IsZero() {
		return view == (ObservationView{})
	}
	return view.Severity.Valid() && !view.ObservedAt.IsZero() && view.Scanner.Validate() == nil
}

func validComparability(value assessmentsnapshot.Comparability) bool {
	return value == assessmentsnapshot.Comparable || value == assessmentsnapshot.PartiallyComparable || value == assessmentsnapshot.NotComparable
}

func comparisonItemID(comparisonID, identityID shared.ID) shared.ID {
	digest := sha256.Sum256([]byte("synapse:assessment-comparison-item:v1\x00" + comparisonID.String() + "\x00" + identityID.String()))
	return shared.ID("comparison-item-" + hex.EncodeToString(digest[:16]))
}

func canonicalItemIDs(values []shared.ID) []shared.ID {
	seen := map[shared.ID]struct{}{}
	result := make([]shared.ID, 0, len(values))
	for _, value := range values {
		if value.IsZero() {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}

func equalItemIDs(left, right []shared.ID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func canonicalReviewCandidates(values []ReviewCandidateView) []ReviewCandidateView {
	byID := map[shared.ID][]shared.ID{}
	for _, value := range values {
		if value.ID.IsZero() {
			continue
		}
		byID[value.ID] = append(byID[value.ID], value.SourceObservationIDs...)
	}
	result := make([]ReviewCandidateView, 0, len(byID))
	for id, sourceIDs := range byID {
		result = append(result, ReviewCandidateView{ID: id, SourceObservationIDs: canonicalItemIDs(sourceIDs)})
	}
	sort.Slice(result, func(left, right int) bool { return result[left].ID < result[right].ID })
	return result
}

func equalReviewCandidates(left, right []ReviewCandidateView) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].ID != right[index].ID || !equalItemIDs(left[index].SourceObservationIDs, right[index].SourceObservationIDs) {
			return false
		}
	}
	return true
}

func containsItemID(values []shared.ID, expected shared.ID) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func canonicalMatchMethods(values []findinglineage.MatchMethod) []findinglineage.MatchMethod {
	seen := map[findinglineage.MatchMethod]struct{}{}
	result := make([]findinglineage.MatchMethod, 0, len(values))
	for _, value := range values {
		if !value.Valid() {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}

func equalMatchMethods(left, right []findinglineage.MatchMethod) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func hashOutput(comparison *Comparison, items []Item, summary Summary) (string, error) {
	payload, err := json.Marshal(struct {
		ComparisonID string  `json:"comparison_id"`
		InputHash    string  `json:"input_hash"`
		Items        []Item  `json:"items"`
		Mode         Mode    `json:"mode"`
		Summary      Summary `json:"summary"`
	}{comparison.ID.String(), comparison.InputHash, items, comparison.Mode, summary})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("synapse:assessment-comparison-output:v1\x00"), payload...))
	return hex.EncodeToString(digest[:]), nil
}

func validReason(value string) bool {
	if len(value) == 0 || len(value) > 64 || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if char != '_' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}
