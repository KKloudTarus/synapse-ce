package promotion

import (
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/verdict"
)

// PromotionEvent is the immutable record of an applied finding-priority change.
// It captures the claim that was accepted, the exact before/after priority, and
// the sealed version of the finding at the time of application so that the
// lifecycle is fully reconstructable.
//
// Events are append-only and never mutated. Reversals produce a new event whose
// AfterPriority restores the prior event's BeforePriority.
// PromotionEvent is the immutable record of an applied finding-priority change.
// It captures the claim that was accepted, the exact before/after priority, and
// the sealed version of the finding at the time of application so that the
// lifecycle is fully reconstructable.
//
// Events are append-only and never mutated. Reversals produce a new event whose
// AfterPriority restores the prior event's BeforePriority.
type PromotionEvent struct {
	// ID is the stable event identity (used for prior-escalation references).
	ID shared.ID

	// EngagementID scopes the event to an engagement (tenant enforcement is at
	// the context/store chokepoint via shared.WithTenant/shared.TenantFrom; the
	// event itself carries only the engagement boundary).
	EngagementID shared.ID

	// JudgmentID identifies the judgment whose sealed verdict cleared the
	// evidence bar for this promotion. Used for idempotency (tenant+judgment)
	// so a single judgment cannot produce multiple events.
	JudgmentID shared.ID

	// FindingID and FindingVersion identify the exact finding snapshot this
	// event applies to. The version is the finding's optimistic-concurrency
	// token BEFORE the priority was moved.
	FindingID      shared.ID
	FindingVersion int

	// AfterFindingVersion is the finding's optimistic-concurrency token AFTER
	// the priority was moved. For mutating effects (escalate/de_escalate) this
	// is FindingVersion+1; for flag_for_review this equals FindingVersion
	// (no version bump).
	AfterFindingVersion int

	// Rule is the stable promotion.* policy key (e.g. promotion.escalate.runtime_reachable_exposed).
	Rule string

	// Effect reuses the judgment vocabulary: escalate, de_escalate, or
	// flag_for_review. A domain-to-domain import of judgment.PromotionChange is
	// the canonical path so claim and lifecycle can never drift.
	Effect judgment.PromotionChange

	// BeforePriority and AfterPriority record the exact priority movement.
	// For flag_for_review, Before == After (no mutation, no version bump on
	// the finding).
	BeforePriority int
	AfterPriority  int

	// Inputs are the typed records that supported this decision. They are
	// persisted verbatim from the validated claim. The constructor makes a
	// defensive copy so the caller cannot mutate the stored slice.
	Inputs []judgment.PromotionInput

	// Fingerprint is the deterministic SHA-256 digest of the claim material.
	// Combined with JudgmentID it makes Apply idempotent: a second call with
	// the same judgment and fingerprint returns the existing event without
	// side effects.
	Fingerprint string

	// VerdictScore is the sealed evidence score from the judgment that
	// cleared the promotion gate. Zero when not available (e.g. deterministic
	// unassisted rules).
	VerdictScore int

	// VerdictRationale is the sealed rationale from the judgment, if any.
	// Stored as-is; never rendered into a report path.
	VerdictRationale string

	// EvidenceID is the sealed evidence artifact that attests this promotion.
	// Empty when the promotion was produced by a deterministic rule that did
	// not seal a separate evidence record.
	EvidenceID shared.ID

	// Verifier identifies the human or service identity whose sealed verdict
	// cleared the evidence bar. Empty for deterministic unassisted rules.
	Verifier string

	// Uncertainty carries the sorted distinct tokens from the claim that
	// describe why this promotion was flagged for review rather than applied
	// deterministically. Empty for deterministic effects (escalate/de_escalate).
	// Preserved from the validated PromotionClaim so that event replay can
	// round-trip through claim validation without losing semantics.
	Uncertainty []string

	// AppliedBy is the actor (human or service identity) that applied this
	// event. Empty means system/unknown.
	AppliedBy string

	// AppliedAt is the wall-clock time of application (append-only; never updated).
	AppliedAt time.Time
}

// NewPromotionEvent validates inputs and builds an immutable event record.
// The id and now parameters are supplied by the use case layer (deterministic,
// testable). Returns shared.ErrValidation on any invariant violation.
// NewPromotionEvent validates inputs and builds an immutable event record.
// The id and now parameters are supplied by the use case layer (deterministic,
// testable). Returns shared.ErrValidation on any invariant violation.
//
// Inputs are defensively copied on construction; the caller can safely reuse or
// mutate the original slice after this call returns.
//
// For escalating/de-escalating effects the afterFindingVersion must be
// findingVersion+1; for flag_for_review it must equal findingVersion.
func NewPromotionEvent(
	id, engagementID, judgmentID, findingID shared.ID,
	findingVersion, afterFindingVersion int,
	rule string,
	effect judgment.PromotionChange,
	beforePriority, afterPriority int,
	inputs []judgment.PromotionInput,
	fingerprint string,
	verdictScore int,
	verdictRationale string,
	evidenceID shared.ID,
	verifier string,
	uncertainty []string,
	appliedBy string,
	now time.Time,
) (PromotionEvent, error) {
	if id.IsZero() {
		return PromotionEvent{}, fmt.Errorf("%w: promotion event id is required", shared.ErrValidation)
	}
	if engagementID.IsZero() {
		return PromotionEvent{}, fmt.Errorf("%w: promotion event engagement id is required", shared.ErrValidation)
	}
	if judgmentID.IsZero() {
		return PromotionEvent{}, fmt.Errorf("%w: promotion event judgment id is required", shared.ErrValidation)
	}
	if findingID.IsZero() {
		return PromotionEvent{}, fmt.Errorf("%w: promotion event finding id is required", shared.ErrValidation)
	}

	// Round-trip through PromotionClaim.Validate to reuse its canonical
	// validation of fingerprint format (lowercase SHA-256), known rule/effect,
	// input kinds/IDs/order/uniqueness/count, uncertainty semantics, and
	// effect-specific priority constraints. This avoids duplicating validation
	// logic and ensures the event is a faithful snapshot of a valid claim.
	claim := judgment.PromotionClaim{
		FindingID:      findingID,
		Rule:           rule,
		Inputs:         inputs,
		Proposed:       effect,
		Uncertainty:    uncertainty,
		Fingerprint:    fingerprint,
		FindingVersion: findingVersion,
		BeforePriority: beforePriority,
		AfterPriority:  afterPriority,
	}
	if err := claim.Validate(); err != nil {
		return PromotionEvent{}, fmt.Errorf("promotion event claim validation: %w", err)
	}

	// AfterFindingVersion: mutating effects bump by 1; flag_for_review does not.
	if effect == judgment.PromotionFlagForReview {
		if afterFindingVersion != findingVersion {
			return PromotionEvent{}, fmt.Errorf("%w: review flag must not bump finding version (got %d, want %d)", shared.ErrValidation, afterFindingVersion, findingVersion)
		}
	} else {
		if afterFindingVersion != findingVersion+1 {
			return PromotionEvent{}, fmt.Errorf("%w: mutating effect must bump finding version by 1 (got %d, want %d)", shared.ErrValidation, afterFindingVersion, findingVersion+1)
		}
	}

	if verdictScore < verdict.EvidenceThreshold || verdictScore > 100 {
		return PromotionEvent{}, fmt.Errorf("%w: promotion verdict score must be %d..100, got %d", shared.ErrValidation, verdict.EvidenceThreshold, verdictScore)
	}
	verifier = strings.TrimSpace(verifier)
	if verifier == "" || len(verifier) > 256 {
		return PromotionEvent{}, fmt.Errorf("%w: promotion verifier is required and must be at most 256 bytes", shared.ErrValidation)
	}
	verdictRationale = strings.TrimSpace(verdictRationale)
	if verdictRationale == "" || len(verdictRationale) > verdict.MaxRationaleBytes {
		return PromotionEvent{}, fmt.Errorf("%w: promotion verdict rationale is required and must be at most %d bytes", shared.ErrValidation, verdict.MaxRationaleBytes)
	}
	if evidenceID.IsZero() {
		return PromotionEvent{}, fmt.Errorf("%w: promotion evidence id is required", shared.ErrValidation)
	}
	appliedBy = strings.TrimSpace(appliedBy)
	if appliedBy == "" {
		return PromotionEvent{}, fmt.Errorf("%w: promotion applied-by actor is required", shared.ErrValidation)
	}

	// Defensive-copy the inputs and uncertainty slices so the caller cannot
	// mutate stored state.
	inputsCopy := make([]judgment.PromotionInput, len(inputs))
	copy(inputsCopy, inputs)

	uncertaintyCopy := make([]string, len(uncertainty))
	copy(uncertaintyCopy, uncertainty)

	return PromotionEvent{
		ID:                  id,
		EngagementID:        engagementID,
		JudgmentID:          judgmentID,
		FindingID:           findingID,
		FindingVersion:      findingVersion,
		AfterFindingVersion: afterFindingVersion,
		Rule:                rule,
		Effect:              effect,
		BeforePriority:      beforePriority,
		AfterPriority:       afterPriority,
		Inputs:              inputsCopy,
		Fingerprint:         fingerprint,
		VerdictScore:        verdictScore,
		VerdictRationale:    verdictRationale,
		EvidenceID:          evidenceID,
		Verifier:            verifier,
		Uncertainty:         uncertaintyCopy,
		AppliedBy:           appliedBy,
		AppliedAt:           now,
	}, nil
}

// Equals reports whether two PromotionEvents are semantically identical on all
// immutable provenance and semantic fields. Only generated fields that retries
// legitimately regenerate (EventID and AppliedAt) are excluded. Verifier, VerdictScore,
// VerdictRationale, and EvidenceID are sealed provenance from the judgment
// that cleared the promotion gate — altering any of them means the replay
// carries different provenance and must not be treated as idempotent.
// Used for exact-replay detection in memory and postgres stores.
func (a PromotionEvent) Equals(b PromotionEvent) bool {
	if a.EngagementID != b.EngagementID ||
		a.JudgmentID != b.JudgmentID ||
		a.FindingID != b.FindingID ||
		a.FindingVersion != b.FindingVersion ||
		a.AfterFindingVersion != b.AfterFindingVersion ||
		a.Rule != b.Rule ||
		a.Effect != b.Effect ||
		a.BeforePriority != b.BeforePriority ||
		a.AfterPriority != b.AfterPriority ||
		a.Fingerprint != b.Fingerprint ||
		a.Verifier != b.Verifier ||
		a.VerdictScore != b.VerdictScore ||
		a.VerdictRationale != b.VerdictRationale ||
		a.EvidenceID != b.EvidenceID ||
		a.AppliedBy != b.AppliedBy {
		return false
	}
	if len(a.Inputs) != len(b.Inputs) {
		return false
	}
	for i := range a.Inputs {
		if a.Inputs[i] != b.Inputs[i] {
			return false
		}
	}
	if len(a.Uncertainty) != len(b.Uncertainty) {
		return false
	}
	for i := range a.Uncertainty {
		if a.Uncertainty[i] != b.Uncertainty[i] {
			return false
		}
	}
	return true
}
