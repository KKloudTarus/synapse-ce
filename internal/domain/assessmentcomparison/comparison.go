package assessmentcomparison

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentcycle"
	"github.com/KKloudTarus/synapse-ce/internal/domain/assessmentsnapshot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/findinglineage"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	AlgorithmVersionV1      = 1
	CoveragePolicyVersionV1 = 1
)

type Mode string

const (
	ModeLifecycle Mode = "lifecycle"
	ModeNeutral   Mode = "neutral_diff"
)

func (mode Mode) Valid() bool { return mode == ModeLifecycle || mode == ModeNeutral }

const (
	ReasonDirected                    = "directed"
	ReasonNeutralSibling              = "neutral_sibling"
	ReasonNeutralReverse              = "neutral_reverse"
	ReasonSameSnapshot                = "same_snapshot"
	ReasonCrossCycle                  = "cross_cycle"
	ReasonSnapshotNotFinalized        = "snapshot_not_finalized"
	ReasonLifecycleReverse            = "lifecycle_reverse"
	ReasonLifecycleSibling            = "lifecycle_sibling"
	ReasonLifecycleDirectionAvailable = "lifecycle_direction_available"
	ReasonMissingRelationship         = "missing_relationship"
)

type PairDecision struct {
	Allowed    bool
	ReasonCode string
}

func DecidePair(mode Mode, baseline, current *assessmentsnapshot.Snapshot, members []assessmentcycle.Member) (PairDecision, error) {
	if !mode.Valid() || baseline == nil || current == nil {
		return PairDecision{}, fmt.Errorf("%w: comparison mode and snapshots are required", shared.ErrValidation)
	}
	if baseline.ID == current.ID {
		return PairDecision{ReasonCode: ReasonSameSnapshot}, nil
	}
	if baseline.TenantID != current.TenantID || baseline.CycleID != current.CycleID {
		return PairDecision{ReasonCode: ReasonCrossCycle}, nil
	}
	if !immutableSnapshot(baseline) || !immutableSnapshot(current) {
		return PairDecision{ReasonCode: ReasonSnapshotNotFinalized}, nil
	}

	direction, err := lifecycleDirection(baseline, current, members)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return PairDecision{ReasonCode: ReasonMissingRelationship}, nil
		}
		return PairDecision{}, err
	}
	if mode == ModeLifecycle {
		switch direction {
		case 1:
			return PairDecision{Allowed: true, ReasonCode: ReasonDirected}, nil
		case -1:
			return PairDecision{ReasonCode: ReasonLifecycleReverse}, nil
		default:
			return PairDecision{ReasonCode: ReasonLifecycleSibling}, nil
		}
	}
	if direction == 1 {
		return PairDecision{ReasonCode: ReasonLifecycleDirectionAvailable}, nil
	}
	if direction == -1 {
		return PairDecision{Allowed: true, ReasonCode: ReasonNeutralReverse}, nil
	}
	return PairDecision{Allowed: true, ReasonCode: ReasonNeutralSibling}, nil
}

func lifecycleDirection(baseline, current *assessmentsnapshot.Snapshot, members []assessmentcycle.Member) (int, error) {
	if baseline.AssessmentID == current.AssessmentID {
		switch {
		case baseline.SnapshotNumber < current.SnapshotNumber:
			return 1, nil
		case baseline.SnapshotNumber > current.SnapshotNumber:
			return -1, nil
		default:
			return 0, fmt.Errorf("%w: snapshots in one assessment cannot share a number", shared.ErrValidation)
		}
	}
	forward, forwardErr := assessmentcycle.IsAncestor(members, baseline.AssessmentID, current.AssessmentID)
	if forwardErr != nil && !errors.Is(forwardErr, shared.ErrNotFound) {
		return 0, forwardErr
	}
	if forward {
		return 1, nil
	}
	reverse, reverseErr := assessmentcycle.IsAncestor(members, current.AssessmentID, baseline.AssessmentID)
	if reverseErr != nil && !errors.Is(reverseErr, shared.ErrNotFound) {
		return 0, reverseErr
	}
	if reverse {
		return -1, nil
	}
	if forwardErr != nil || reverseErr != nil {
		return 0, fmt.Errorf("%w: snapshot assessment is absent from cycle relationships", shared.ErrNotFound)
	}
	return 0, nil
}

func immutableSnapshot(snapshot *assessmentsnapshot.Snapshot) bool {
	return snapshot.Lifecycle == assessmentsnapshot.LifecycleFinalized || snapshot.Lifecycle == assessmentsnapshot.LifecycleSuperseded
}

type Presence string

const (
	PresenceNew          Presence = "new"
	PresenceDetected     Presence = "still_detected"
	PresenceNotDetected  Presence = "not_detected_under_comparable_coverage"
	PresenceNotEvaluated Presence = "not_evaluated"
	PresenceReopened     Presence = "reopened"
	PresenceNeedsReview  Presence = "needs_review"
)

type NeutralPresence string

const (
	NeutralOnlyA       NeutralPresence = "only_in_a"
	NeutralBoth        NeutralPresence = "both"
	NeutralOnlyB       NeutralPresence = "only_in_b"
	NeutralNeedsReview NeutralPresence = "needs_review"
)

func (presence Presence) Valid() bool {
	switch presence {
	case PresenceNew, PresenceDetected, PresenceNotDetected, PresenceNotEvaluated, PresenceReopened, PresenceNeedsReview:
		return true
	}
	return false
}

func (presence NeutralPresence) Valid() bool {
	switch presence {
	case NeutralOnlyA, NeutralBoth, NeutralOnlyB, NeutralNeedsReview:
		return true
	}
	return false
}

type FixedBasis string

const (
	FixedByComparableAbsence    FixedBasis = "comparable_absence"
	FixedByExplicitVerification FixedBasis = "explicit_verification"
)

func (basis FixedBasis) Valid() bool {
	return basis == FixedByComparableAbsence || basis == FixedByExplicitVerification
}

type ChangeFlag string

const (
	SeverityIncreased       ChangeFlag = "severity_increased"
	SeverityDecreased       ChangeFlag = "severity_decreased"
	ComponentVersionChanged ChangeFlag = "component_version_changed"
	LocationChanged         ChangeFlag = "location_changed"
	ReachabilityChanged     ChangeFlag = "reachability_changed"
	EvidenceChanged         ChangeFlag = "evidence_changed"
	ScannerChanged          ChangeFlag = "scanner_changed"
	RuleProfileChanged      ChangeFlag = "rule_profile_changed"
	AdvisoryChanged         ChangeFlag = "advisory_changed"
)

func (flag ChangeFlag) Valid() bool {
	switch flag {
	case SeverityIncreased, SeverityDecreased, ComponentVersionChanged, LocationChanged, ReachabilityChanged,
		EvidenceChanged, ScannerChanged, RuleProfileChanged, AdvisoryChanged:
		return true
	}
	return false
}

type HistoryState struct {
	Order                int64
	Observed             bool
	ComparableAbsence    bool
	VerifiedRemediation  bool
	Ambiguous            bool
	VerificationDecision shared.ID
}

type ClassifyInput struct {
	IdentityID             shared.ID
	Baseline               *findinglineage.Observation
	Current                *findinglineage.Observation
	CurrentCoverage        assessmentsnapshot.Comparability
	Ambiguous              bool
	History                []HistoryState
	VerificationID         shared.ID
	VerificationState      string
	VerificationRemediated bool
	BaselineActionable     bool
	CurrentActionable      bool
	BaselineRiskMilli      int64
	CurrentRiskMilli       int64
}

type Item struct {
	ID                    shared.ID                        `json:"id"`
	Position              int                              `json:"position"`
	IdentityID            shared.ID                        `json:"identity_id"`
	ProducerKind          string                           `json:"producer_kind"`
	FindingKind           string                           `json:"finding_kind"`
	TargetCanonical       string                           `json:"target_canonical"`
	BaselineObservationID shared.ID                        `json:"baseline_observation_id,omitempty"`
	CurrentObservationID  shared.ID                        `json:"current_observation_id,omitempty"`
	BaselineObservation   ObservationView                  `json:"baseline_observation,omitempty"`
	CurrentObservation    ObservationView                  `json:"current_observation,omitempty"`
	Presence              Presence                         `json:"presence,omitempty"`
	NeutralPresence       NeutralPresence                  `json:"neutral_presence,omitempty"`
	ChangeFlags           []ChangeFlag                     `json:"change_flags"`
	CoverageDecision      assessmentsnapshot.Comparability `json:"coverage_decision"`
	MatchMethods          []findinglineage.MatchMethod     `json:"match_methods,omitempty"`
	VerificationID        shared.ID                        `json:"verification_id,omitempty"`
	VerificationState     string                           `json:"verification_state,omitempty"`
	FixedBasis            FixedBasis                       `json:"fixed_basis,omitempty"`
	BaselineActionable    bool                             `json:"baseline_actionable"`
	CurrentActionable     bool                             `json:"current_actionable"`
	ComparableBaseline    bool                             `json:"comparable_baseline"`
	BaselineRiskMilli     int64                            `json:"baseline_risk_milli"`
	CurrentRiskMilli      int64                            `json:"current_risk_milli"`
	ReviewCandidateIDs    []shared.ID                      `json:"review_candidate_ids,omitempty"`
	ReviewCandidates      []ReviewCandidateView            `json:"review_candidates,omitempty"`
}

type ReviewCandidateView struct {
	ID                   shared.ID   `json:"id"`
	SourceObservationIDs []shared.ID `json:"source_observation_ids"`
}

type ObservationView struct {
	Severity         shared.Severity                  `json:"severity"`
	ComponentVersion string                           `json:"component_version,omitempty"`
	Location         string                           `json:"location,omitempty"`
	Reachability     string                           `json:"reachability,omitempty"`
	EvidenceDigest   string                           `json:"evidence_digest,omitempty"`
	Scanner          findinglineage.ScannerProvenance `json:"scanner"`
	ObservedAt       time.Time                        `json:"observed_at"`
}

func ClassifyLifecycle(input ClassifyInput) (Item, error) {
	item, err := newItem(input)
	if err != nil {
		return Item{}, err
	}
	if input.Ambiguous {
		item.Presence = PresenceNeedsReview
		return item, nil
	}
	switch {
	case input.Baseline != nil && input.Current != nil:
		item.Presence = PresenceDetected
		item.ComparableBaseline = true
		item.ChangeFlags = changeFlags(*input.Baseline, *input.Current)
	case input.Baseline != nil:
		if input.CurrentCoverage == assessmentsnapshot.Comparable {
			item.Presence, item.ComparableBaseline = PresenceNotDetected, true
			item.FixedBasis = FixedByComparableAbsence
		} else {
			item.Presence = PresenceNotEvaluated
			if input.VerificationRemediated {
				item.FixedBasis = FixedByExplicitVerification
			}
		}
	case input.Current != nil:
		item.Presence = classifyReturn(input.History)
	default:
		return Item{}, fmt.Errorf("%w: comparison item requires baseline or current presence", shared.ErrValidation)
	}
	return item, nil
}

func ClassifyNeutral(input ClassifyInput) (Item, error) {
	item, err := newItem(input)
	if err != nil {
		return Item{}, err
	}
	if input.Ambiguous {
		item.NeutralPresence = NeutralNeedsReview
		return item, nil
	}
	switch {
	case input.Baseline != nil && input.Current != nil:
		item.NeutralPresence = NeutralBoth
		item.ChangeFlags = changeFlags(*input.Baseline, *input.Current)
	case input.Baseline != nil:
		item.NeutralPresence = NeutralOnlyA
	case input.Current != nil:
		item.NeutralPresence = NeutralOnlyB
	default:
		return Item{}, fmt.Errorf("%w: neutral item requires presence in either snapshot", shared.ErrValidation)
	}
	return item, nil
}

func newItem(input ClassifyInput) (Item, error) {
	if input.IdentityID.IsZero() || input.BaselineRiskMilli < 0 || input.CurrentRiskMilli < 0 {
		return Item{}, fmt.Errorf("%w: comparison item identity and risk are invalid", shared.ErrValidation)
	}
	item := Item{
		IdentityID: input.IdentityID, VerificationID: input.VerificationID, VerificationState: input.VerificationState,
		BaselineActionable: input.BaselineActionable, CurrentActionable: input.CurrentActionable,
		BaselineRiskMilli: input.BaselineRiskMilli, CurrentRiskMilli: input.CurrentRiskMilli, ChangeFlags: []ChangeFlag{},
		CoverageDecision: assessmentsnapshot.NotComparable,
	}
	if input.Baseline != nil {
		item.BaselineObservationID = input.Baseline.ID
		item.BaselineObservation = projectObservation(*input.Baseline)
		item.ProducerKind, item.FindingKind, item.TargetCanonical = input.Baseline.ProducerKind, input.Baseline.FindingKind, input.Baseline.TargetCanonical
	}
	if input.Current != nil {
		item.CurrentObservationID = input.Current.ID
		item.CurrentObservation = projectObservation(*input.Current)
		if item.ProducerKind == "" {
			item.ProducerKind, item.FindingKind, item.TargetCanonical = input.Current.ProducerKind, input.Current.FindingKind, input.Current.TargetCanonical
		} else if item.ProducerKind != input.Current.ProducerKind || item.FindingKind != input.Current.FindingKind || item.TargetCanonical != input.Current.TargetCanonical {
			return Item{}, fmt.Errorf("%w: comparison observations disagree on immutable identity metadata", shared.ErrValidation)
		}
	}
	return item, nil
}

func projectObservation(observation findinglineage.Observation) ObservationView {
	return ObservationView{
		Severity: observation.Severity, ComponentVersion: observation.ComponentVersion, Location: observation.Location,
		Reachability: observation.Reachability, EvidenceDigest: observation.EvidenceDigest, Scanner: observation.ScannerProvenance,
		ObservedAt: observation.ObservedAt,
	}
}

func classifyReturn(history []HistoryState) Presence {
	if len(history) == 0 {
		return PresenceNew
	}
	ordered := append([]HistoryState(nil), history...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Order < ordered[j].Order })
	for _, state := range ordered {
		if state.Ambiguous {
			return PresenceNeedsReview
		}
	}
	seen := false
	for index := len(ordered) - 1; index >= 0; index-- {
		state := ordered[index]
		if state.ComparableAbsence || state.VerifiedRemediation {
			return PresenceReopened
		}
		if state.Observed {
			seen = true
			break
		}
	}
	if seen {
		return PresenceDetected
	}
	return PresenceNew
}

func changeFlags(baseline, current findinglineage.Observation) []ChangeFlag {
	flags := make([]ChangeFlag, 0, 9)
	baselineRank, currentRank := shared.SeverityRank(baseline.Severity), shared.SeverityRank(current.Severity)
	if currentRank > baselineRank {
		flags = append(flags, SeverityIncreased)
	} else if currentRank < baselineRank {
		flags = append(flags, SeverityDecreased)
	}
	if baseline.ComponentVersion != current.ComponentVersion {
		flags = append(flags, ComponentVersionChanged)
	}
	if baseline.Location != current.Location {
		flags = append(flags, LocationChanged)
	}
	if baseline.Reachability != current.Reachability {
		flags = append(flags, ReachabilityChanged)
	}
	if baseline.EvidenceDigest != current.EvidenceDigest {
		flags = append(flags, EvidenceChanged)
	}
	if baseline.ScannerProvenance.ToolName != current.ScannerProvenance.ToolName || baseline.ScannerProvenance.ToolVersion != current.ScannerProvenance.ToolVersion {
		flags = append(flags, ScannerChanged)
	}
	if baseline.ScannerProvenance.LaneKey != current.ScannerProvenance.LaneKey {
		flags = append(flags, RuleProfileChanged)
	}
	if baseline.ScannerProvenance.RuleID != current.ScannerProvenance.RuleID {
		flags = append(flags, AdvisoryChanged)
	}
	return flags
}

type Ratio struct {
	Numerator   int64  `json:"numerator"`
	Denominator int64  `json:"denominator"`
	NAReason    string `json:"na_reason,omitempty"`
}

type Summary struct {
	ComparisonID       shared.ID      `json:"comparison_id"`
	BaselineSnapshotID shared.ID      `json:"baseline_snapshot_id"`
	CurrentSnapshotID  shared.ID      `json:"current_snapshot_id"`
	RiskModelVersion   int            `json:"risk_model_version"`
	FixedRate          Ratio          `json:"fixed_rate"`
	CountReduction     Ratio          `json:"count_reduction"`
	RiskReduction      Ratio          `json:"risk_reduction"`
	FixedCount         int64          `json:"fixed_count"`
	BaselineCount      int64          `json:"baseline_count"`
	CurrentCount       int64          `json:"current_count"`
	BaselineRisk       int64          `json:"baseline_risk"`
	CurrentRisk        int64          `json:"current_risk"`
	NewCount           int64          `json:"new_count"`
	ReopenedCount      int64          `json:"reopened_count"`
	StillDetectedCount int64          `json:"still_detected_count"`
	NotEvaluatedCount  int64          `json:"not_evaluated_count"`
	ReviewCount        int64          `json:"review_count"`
	NewRisk            int64          `json:"new_risk"`
	ReopenedRisk       int64          `json:"reopened_risk"`
	BaselineSeverity   SeverityCounts `json:"baseline_severity"`
	CurrentSeverity    SeverityCounts `json:"current_severity"`
}

type SeverityCounts struct {
	Critical int64 `json:"critical"`
	High     int64 `json:"high"`
	Medium   int64 `json:"medium"`
	Low      int64 `json:"low"`
	Info     int64 `json:"info"`
	Unknown  int64 `json:"unknown"`
}

func Summarize(items []Item) Summary {
	var summary Summary
	for _, item := range items {
		if item.BaselineActionable {
			summary.BaselineCount++
			summary.BaselineRisk += item.BaselineRiskMilli
			summary.BaselineSeverity.add(item.BaselineObservation.Severity)
			if item.ComparableBaseline {
				summary.FixedRate.Denominator++
			}
		}
		if item.CurrentActionable {
			summary.CurrentCount++
			summary.CurrentRisk += item.CurrentRiskMilli
			summary.CurrentSeverity.add(item.CurrentObservation.Severity)
		}
		if item.Presence == PresenceNotDetected && item.BaselineActionable {
			summary.FixedCount++
			summary.FixedRate.Numerator++
		}
		switch item.Presence {
		case PresenceNew:
			summary.NewCount++
			summary.NewRisk += item.CurrentRiskMilli
		case PresenceReopened:
			summary.ReopenedCount++
			summary.ReopenedRisk += item.CurrentRiskMilli
		case PresenceDetected:
			summary.StillDetectedCount++
		case PresenceNotEvaluated:
			summary.NotEvaluatedCount++
		case PresenceNeedsReview:
			summary.ReviewCount++
		}
		if item.NeutralPresence == NeutralNeedsReview || len(item.ReviewCandidateIDs) > 0 && item.Presence != PresenceNeedsReview {
			summary.ReviewCount++
		}
	}
	summary.CountReduction = Ratio{Numerator: summary.BaselineCount - summary.CurrentCount, Denominator: summary.BaselineCount}
	summary.RiskReduction = Ratio{Numerator: summary.BaselineRisk - summary.CurrentRisk, Denominator: summary.BaselineRisk}
	if summary.FixedRate.Denominator == 0 {
		summary.FixedRate.NAReason = "no_comparable_actionable_baseline"
	}
	if summary.CountReduction.Denominator == 0 {
		summary.CountReduction.NAReason = "no_actionable_baseline"
	}
	if summary.RiskReduction.Denominator <= 0 {
		summary.RiskReduction.NAReason = "non_positive_baseline_risk"
	}
	return summary
}

func (counts *SeverityCounts) add(severity shared.Severity) {
	switch severity {
	case shared.SeverityCritical:
		counts.Critical++
	case shared.SeverityHigh:
		counts.High++
	case shared.SeverityMedium:
		counts.Medium++
	case shared.SeverityLow:
		counts.Low++
	case shared.SeverityInfo:
		counts.Info++
	default:
		counts.Unknown++
	}
}

type SnapshotHashRef struct {
	ID          shared.ID
	ContentHash string
}

type RelationshipRef struct {
	AssessmentID        shared.ID
	PredecessorID       shared.ID
	RelationshipVersion int64
}

type GenerationInput struct {
	Mode                    Mode
	Baseline                SnapshotHashRef
	Current                 SnapshotHashRef
	HistorySnapshots        []SnapshotHashRef
	Relationships           []RelationshipRef
	AlgorithmVersion        int
	FingerprintVersion      int
	RiskModelVersion        int
	CoveragePolicyVersion   int
	ActiveOverrideIDs       []shared.ID
	MatchCandidateIDs       []shared.ID
	VerificationDecisionIDs []shared.ID
}

func HashGenerationInput(input GenerationInput) ([]byte, string, error) {
	if !input.Mode.Valid() || input.Baseline.ID.IsZero() || input.Current.ID.IsZero() || !validDigest(input.Baseline.ContentHash) || !validDigest(input.Current.ContentHash) {
		return nil, "", fmt.Errorf("%w: comparison snapshots and mode are invalid", shared.ErrValidation)
	}
	if input.AlgorithmVersion <= 0 || input.FingerprintVersion <= 0 || input.RiskModelVersion <= 0 || input.CoveragePolicyVersion <= 0 {
		return nil, "", fmt.Errorf("%w: comparison generation versions are required", shared.ErrValidation)
	}
	relationships := make([]findinglineage.CanonicalValue, len(input.Relationships))
	for index, relationship := range input.Relationships {
		if relationship.AssessmentID.IsZero() || relationship.RelationshipVersion <= 0 {
			return nil, "", fmt.Errorf("%w: comparison relationship is invalid", shared.ErrValidation)
		}
		fields := map[string]findinglineage.CanonicalValue{
			"assessment_id": findinglineage.Text(relationship.AssessmentID.String()),
			"version":       findinglineage.Integer(relationship.RelationshipVersion),
		}
		if !relationship.PredecessorID.IsZero() {
			fields["predecessor_id"] = findinglineage.Text(relationship.PredecessorID.String())
		}
		relationships[index] = findinglineage.Object(fields)
	}
	fields := map[string]findinglineage.CanonicalValue{
		"algorithm_version":       findinglineage.Integer(int64(input.AlgorithmVersion)),
		"baseline_snapshot_hash":  findinglineage.Text(input.Baseline.ContentHash),
		"baseline_snapshot_id":    findinglineage.Text(input.Baseline.ID.String()),
		"coverage_policy_version": findinglineage.Integer(int64(input.CoveragePolicyVersion)),
		"current_snapshot_hash":   findinglineage.Text(input.Current.ContentHash),
		"current_snapshot_id":     findinglineage.Text(input.Current.ID.String()),
		"fingerprint_version":     findinglineage.Integer(int64(input.FingerprintVersion)),
		"mode":                    findinglineage.Text(string(input.Mode)),
		"risk_model_version":      findinglineage.Integer(int64(input.RiskModelVersion)),
	}
	if len(relationships) > 0 {
		fields["relationships"] = findinglineage.OrderedArray(relationships...)
	}
	if len(input.HistorySnapshots) > 0 {
		history := make([]findinglineage.CanonicalValue, len(input.HistorySnapshots))
		for index, snapshot := range input.HistorySnapshots {
			if snapshot.ID.IsZero() || !validDigest(snapshot.ContentHash) || snapshot.ID == input.Baseline.ID || snapshot.ID == input.Current.ID {
				return nil, "", fmt.Errorf("%w: comparison history snapshot is invalid", shared.ErrValidation)
			}
			history[index] = findinglineage.Object(map[string]findinglineage.CanonicalValue{
				"content_hash": findinglineage.Text(snapshot.ContentHash),
				"id":           findinglineage.Text(snapshot.ID.String()),
			})
		}
		fields["history_snapshots"] = findinglineage.OrderedArray(history...)
	}
	if values := canonicalIDs(input.ActiveOverrideIDs); len(values) > 0 {
		fields["active_override_ids"] = findinglineage.StringSet(values...)
	}
	if values := canonicalIDs(input.MatchCandidateIDs); len(values) > 0 {
		fields["match_candidate_ids"] = findinglineage.StringSet(values...)
	}
	if values := canonicalIDs(input.VerificationDecisionIDs); len(values) > 0 {
		fields["verification_decision_ids"] = findinglineage.StringSet(values...)
	}
	canonical, err := findinglineage.CanonicalizeFingerprintV1(findinglineage.FingerprintCanonicalInputV1{
		CanonicalizationVersion: findinglineage.CanonicalizationVersionV1,
		ProducerKind:            "assessment_comparison", TargetIdentitySchemaVersion: 1,
		TargetIdentityCanonical: "comparison-input", IdentityFields: fields,
	})
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(append([]byte("synapse:assessment-comparison-input:v1\x00"), canonical.IdentityFields...))
	return canonical.IdentityFields, hex.EncodeToString(digest[:]), nil
}

func canonicalIDs(values []shared.ID) []string {
	unique := map[string]struct{}{}
	for _, value := range values {
		if !value.IsZero() {
			unique[value.String()] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
