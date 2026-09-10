package assessmentrelationship

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const (
	SchemaVersion        = 1
	minCandidateLifetime = 24 * time.Hour
	maxCandidateLifetime = 90 * 24 * time.Hour
)

type Confidence string

const (
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

func (confidence Confidence) Valid() bool {
	return confidence == ConfidenceMedium || confidence == ConfidenceHigh
}

type SignalKind string

const (
	SignalExactBoundary        SignalKind = "exact_frozen_boundary"
	SignalImportedReference    SignalKind = "explicit_imported_reference"
	SignalTrustedManifest      SignalKind = "trusted_manifest_compatible"
	SignalDeterministicOverlap SignalKind = "deterministic_finding_overlap"
)

func (kind SignalKind) Valid() bool {
	switch kind {
	case SignalExactBoundary, SignalImportedReference, SignalTrustedManifest, SignalDeterministicOverlap:
		return true
	default:
		return false
	}
}

type Signal struct {
	Kind          SignalKind `json:"kind"`
	EvidenceHash  string     `json:"evidence_hash"`
	MatchCount    int        `json:"match_count,omitempty"`
	ScoreMilli    int        `json:"score_milli,omitempty"`
	SchemaVersion int        `json:"schema_version"`
}

func (signal Signal) Validate() error {
	if !signal.Kind.Valid() || !validDigest(signal.EvidenceHash) || signal.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: relationship candidate signal is invalid", shared.ErrValidation)
	}
	if signal.MatchCount < 0 || signal.ScoreMilli < 0 || signal.ScoreMilli > 1000 {
		return fmt.Errorf("%w: relationship candidate signal score is invalid", shared.ErrValidation)
	}
	switch signal.Kind {
	case SignalExactBoundary:
		if signal.MatchCount != 0 || signal.ScoreMilli != 0 {
			return fmt.Errorf("%w: exact boundary signal score is invalid", shared.ErrValidation)
		}
	case SignalImportedReference:
		if signal.MatchCount != 1 || signal.ScoreMilli != 1000 {
			return fmt.Errorf("%w: imported relationship signal is invalid", shared.ErrValidation)
		}
	case SignalTrustedManifest:
		if signal.MatchCount < 1 || signal.ScoreMilli != 1000 {
			return fmt.Errorf("%w: trusted manifest signal is invalid", shared.ErrValidation)
		}
	case SignalDeterministicOverlap:
		if signal.MatchCount < 2 || signal.ScoreMilli < 800 {
			return fmt.Errorf("%w: deterministic overlap signal is too weak", shared.ErrValidation)
		}
	}
	return nil
}

type Candidate struct {
	TenantID                       shared.ID
	ID                             shared.ID
	PredecessorCycleID             shared.ID
	PredecessorAssessmentID        shared.ID
	PredecessorRelationshipVersion int64
	PredecessorSnapshotID          shared.ID
	PredecessorSnapshotHash        string
	SuccessorCycleID               shared.ID
	SuccessorAssessmentID          shared.ID
	SuccessorRelationshipVersion   int64
	SuccessorSnapshotID            shared.ID
	SuccessorSnapshotHash          string
	BoundaryKeyHash                string
	Signals                        []Signal
	InputHash                      string
	Confidence                     Confidence
	ExpiresAt                      time.Time
	CreatedBy                      string
	CreatedAt                      time.Time
}

func NewCandidate(candidate Candidate) (Candidate, error) {
	candidate.CreatedBy = strings.TrimSpace(candidate.CreatedBy)
	candidate.Signals = append([]Signal(nil), candidate.Signals...)
	sort.Slice(candidate.Signals, func(left, right int) bool {
		if candidate.Signals[left].Kind != candidate.Signals[right].Kind {
			return candidate.Signals[left].Kind < candidate.Signals[right].Kind
		}
		return candidate.Signals[left].EvidenceHash < candidate.Signals[right].EvidenceHash
	})
	inputHash, err := candidate.ComputeInputHash()
	if err != nil {
		return Candidate{}, err
	}
	candidate.InputHash = inputHash
	return candidate, candidate.Validate()
}

func (candidate Candidate) Validate() error {
	if candidate.TenantID.IsZero() || candidate.ID.IsZero() || candidate.PredecessorCycleID.IsZero() || candidate.PredecessorAssessmentID.IsZero() || candidate.PredecessorSnapshotID.IsZero() || candidate.SuccessorCycleID.IsZero() || candidate.SuccessorAssessmentID.IsZero() || candidate.SuccessorSnapshotID.IsZero() {
		return fmt.Errorf("%w: relationship candidate ownership is required", shared.ErrValidation)
	}
	if candidate.PredecessorCycleID == candidate.SuccessorCycleID || candidate.PredecessorAssessmentID == candidate.SuccessorAssessmentID {
		return fmt.Errorf("%w: relationship candidate subjects must differ", shared.ErrValidation)
	}
	if candidate.PredecessorRelationshipVersion < 1 || candidate.SuccessorRelationshipVersion < 1 {
		return fmt.Errorf("%w: relationship candidate versions are invalid", shared.ErrValidation)
	}
	if !validDigest(candidate.PredecessorSnapshotHash) || !validDigest(candidate.SuccessorSnapshotHash) || !validDigest(candidate.BoundaryKeyHash) || !validDigest(candidate.InputHash) {
		return fmt.Errorf("%w: relationship candidate hashes are invalid", shared.ErrValidation)
	}
	if !candidate.Confidence.Valid() || len(candidate.Signals) < 2 || len(candidate.Signals) > 4 {
		return fmt.Errorf("%w: relationship candidate confidence or signals are invalid", shared.ErrValidation)
	}
	seen := map[SignalKind]bool{}
	qualified := false
	for _, signal := range candidate.Signals {
		if err := signal.Validate(); err != nil {
			return err
		}
		if seen[signal.Kind] {
			return fmt.Errorf("%w: relationship candidate signal is duplicated", shared.ErrValidation)
		}
		seen[signal.Kind] = true
		if signal.Kind != SignalExactBoundary {
			qualified = true
		}
	}
	if !seen[SignalExactBoundary] || !qualified {
		return fmt.Errorf("%w: exact boundary plus a deterministic relationship signal are required", shared.ErrValidation)
	}
	wantConfidence := ConfidenceMedium
	if len(candidate.Signals) >= 3 {
		wantConfidence = ConfidenceHigh
	}
	if candidate.Confidence != wantConfidence {
		return fmt.Errorf("%w: relationship candidate confidence does not match its signals", shared.ErrValidation)
	}
	lifetime := candidate.ExpiresAt.Sub(candidate.CreatedAt)
	if candidate.CreatedAt.IsZero() || lifetime < minCandidateLifetime || lifetime > maxCandidateLifetime || candidate.CreatedBy == "" || candidate.CreatedBy != strings.TrimSpace(candidate.CreatedBy) || utf8.RuneCountInString(candidate.CreatedBy) > 256 {
		return fmt.Errorf("%w: relationship candidate lifecycle metadata is invalid", shared.ErrValidation)
	}
	want, err := candidate.ComputeInputHash()
	if err != nil {
		return err
	}
	if want != candidate.InputHash {
		return fmt.Errorf("%w: relationship candidate input hash mismatch", shared.ErrValidation)
	}
	return nil
}

func (candidate Candidate) ComputeInputHash() (string, error) {
	payload := struct {
		SchemaVersion                  int       `json:"schema_version"`
		TenantID                       shared.ID `json:"tenant_id"`
		PredecessorCycleID             shared.ID `json:"predecessor_cycle_id"`
		PredecessorAssessmentID        shared.ID `json:"predecessor_assessment_id"`
		PredecessorRelationshipVersion int64     `json:"predecessor_relationship_version"`
		PredecessorSnapshotID          shared.ID `json:"predecessor_snapshot_id"`
		PredecessorSnapshotHash        string    `json:"predecessor_snapshot_hash"`
		SuccessorCycleID               shared.ID `json:"successor_cycle_id"`
		SuccessorAssessmentID          shared.ID `json:"successor_assessment_id"`
		SuccessorRelationshipVersion   int64     `json:"successor_relationship_version"`
		SuccessorSnapshotID            shared.ID `json:"successor_snapshot_id"`
		SuccessorSnapshotHash          string    `json:"successor_snapshot_hash"`
		BoundaryKeyHash                string    `json:"boundary_key_hash"`
		Signals                        []Signal  `json:"signals"`
	}{
		SchemaVersion: SchemaVersion, TenantID: candidate.TenantID,
		PredecessorCycleID: candidate.PredecessorCycleID, PredecessorAssessmentID: candidate.PredecessorAssessmentID,
		PredecessorRelationshipVersion: candidate.PredecessorRelationshipVersion, PredecessorSnapshotID: candidate.PredecessorSnapshotID,
		PredecessorSnapshotHash: candidate.PredecessorSnapshotHash, SuccessorCycleID: candidate.SuccessorCycleID,
		SuccessorAssessmentID: candidate.SuccessorAssessmentID, SuccessorRelationshipVersion: candidate.SuccessorRelationshipVersion,
		SuccessorSnapshotID: candidate.SuccessorSnapshotID, SuccessorSnapshotHash: candidate.SuccessorSnapshotHash,
		BoundaryKeyHash: candidate.BoundaryKeyHash, Signals: candidate.Signals,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal relationship candidate input: %w", err)
	}
	return digest(encoded), nil
}

type DecisionAction string

const (
	DecisionConfirm DecisionAction = "confirm"
	DecisionReject  DecisionAction = "reject"
	DecisionDismiss DecisionAction = "dismiss"
)

func (action DecisionAction) Valid() bool {
	return action == DecisionConfirm || action == DecisionReject || action == DecisionDismiss
}

type Decision struct {
	TenantID        shared.ID
	ID              shared.ID
	CandidateID     shared.ID
	Action          DecisionAction
	Actor           string
	Reason          string
	IdempotencyKey  string
	RequestHash     string
	ExpectedVersion int64
	Version         int64
	RepairPlanID    shared.ID
	CreatedAt       time.Time
}

func (decision Decision) Validate() error {
	if decision.TenantID.IsZero() || decision.ID.IsZero() || decision.CandidateID.IsZero() || !decision.Action.Valid() || decision.Actor == "" || decision.Actor != strings.TrimSpace(decision.Actor) || utf8.RuneCountInString(decision.Actor) > 256 || decision.Reason == "" || decision.Reason != strings.TrimSpace(decision.Reason) || utf8.RuneCountInString(decision.Reason) > 2000 || decision.IdempotencyKey == "" || decision.IdempotencyKey != strings.TrimSpace(decision.IdempotencyKey) || utf8.RuneCountInString(decision.IdempotencyKey) > 128 || !validDigest(decision.RequestHash) || decision.ExpectedVersion != 1 || decision.Version != 2 || decision.CreatedAt.IsZero() {
		return fmt.Errorf("%w: relationship candidate decision is invalid", shared.ErrValidation)
	}
	if (decision.Action == DecisionConfirm) != !decision.RepairPlanID.IsZero() {
		return fmt.Errorf("%w: confirmed decision repair plan is invalid", shared.ErrValidation)
	}
	return nil
}

type RepairPlan struct {
	TenantID    shared.ID
	ID          shared.ID
	CandidateID shared.ID
	InputHash   string
	PlanHash    string
	Body        []byte
	CreatedBy   string
	CreatedAt   time.Time
}

func NewRepairPlan(plan RepairPlan) (RepairPlan, error) {
	plan.CreatedBy = strings.TrimSpace(plan.CreatedBy)
	plan.Body = append([]byte(nil), plan.Body...)
	plan.PlanHash = digest(plan.Body)
	return plan, plan.Validate()
}

func (plan RepairPlan) Validate() error {
	if plan.TenantID.IsZero() || plan.ID.IsZero() || plan.CandidateID.IsZero() || !validDigest(plan.InputHash) || !validDigest(plan.PlanHash) || len(plan.Body) == 0 || len(plan.Body) > 8192 || !json.Valid(plan.Body) || plan.CreatedBy == "" || plan.CreatedBy != strings.TrimSpace(plan.CreatedBy) || utf8.RuneCountInString(plan.CreatedBy) > 256 || plan.CreatedAt.IsZero() {
		return fmt.Errorf("%w: relationship repair plan is invalid", shared.ErrValidation)
	}
	if digest(plan.Body) != plan.PlanHash {
		return fmt.Errorf("%w: relationship repair plan hash mismatch", shared.ErrValidation)
	}
	var body struct {
		SchemaVersion int       `json:"schema_version"`
		Command       string    `json:"command"`
		Execution     string    `json:"execution"`
		Requires      string    `json:"requires"`
		CandidateID   shared.ID `json:"candidate_id"`
		InputHash     string    `json:"input_hash"`
	}
	if err := json.Unmarshal(plan.Body, &body); err != nil || body.SchemaVersion != SchemaVersion || body.Command != "assessment_cycle.merge_legacy_relationship" || body.Execution != "blocked" || body.Requires != "separately_approved_move_merge_command" || body.CandidateID != plan.CandidateID || body.InputHash != plan.InputHash {
		return fmt.Errorf("%w: relationship repair plan body is invalid", shared.ErrValidation)
	}
	return nil
}

type Record struct {
	Candidate Candidate
	Decision  *Decision
	Plan      *RepairPlan
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func validDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
