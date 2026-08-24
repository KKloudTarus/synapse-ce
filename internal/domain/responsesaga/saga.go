package responsesaga

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// VerificationOutcome is the result of checking a response's post-condition via telemetry. Note the
// explicit "unknown, insufficient coverage" — the honest answer when the telemetry needed to confirm the
// effect was not observed; it is NOT treated as success.
type VerificationOutcome string

const (
	VerificationSucceeded VerificationOutcome = "succeeded"
	VerificationFailed    VerificationOutcome = "failed"
	VerificationUnknown   VerificationOutcome = "unknown_insufficient_coverage"
	VerificationTimedOut  VerificationOutcome = "timed_out"
	VerificationPending   VerificationOutcome = "" // not yet verified
)

// Valid reports whether v is a known (or the pending zero) outcome.
func (v VerificationOutcome) Valid() bool {
	switch v {
	case VerificationSucceeded, VerificationFailed, VerificationUnknown, VerificationTimedOut, VerificationPending:
		return true
	default:
		return false
	}
}

// ReversibilityClass states how reversible a response is — a reversal COMMAND is not the same as restored
// STATE, so this is declared up front and a rollback still carries its own verified post-condition.
type ReversibilityClass string

const (
	ReversibilityGuaranteed   ReversibilityClass = "guaranteed"
	ReversibilityCompensating ReversibilityClass = "compensating"
	ReversibilityBestEffort   ReversibilityClass = "best_effort"
	ReversibilityIrreversible ReversibilityClass = "irreversible"
)

// Valid reports whether r is a known reversibility class.
func (r ReversibilityClass) Valid() bool {
	switch r {
	case ReversibilityGuaranteed, ReversibilityCompensating, ReversibilityBestEffort, ReversibilityIrreversible:
		return true
	default:
		return false
	}
}

// ResponseAttempt is one at-least-once execution attempt, journaled by the agent BEFORE the side effect so
// a re-delivery is idempotent: the IdempotencyKey dedups a repeated issue of the same attempt, and the
// TargetFingerprint pins exactly what was acted on. It records the command and (once verified) the
// verification outcome.
type ResponseAttempt struct {
	ActionID            shared.ID
	Attempt             int
	IdempotencyKey      string
	Target              TargetFingerprint
	State               SagaState
	CommandOutcome      string
	VerificationOutcome VerificationOutcome
	At                  time.Time
}

// Validate enforces a well-formed attempt.
func (a ResponseAttempt) Validate() error {
	if a.ActionID.IsZero() {
		return fmt.Errorf("%w: response attempt has no action id", shared.ErrValidation)
	}
	if a.Attempt < 1 {
		return fmt.Errorf("%w: response attempt number must be >= 1", shared.ErrValidation)
	}
	if a.IdempotencyKey == "" {
		return fmt.Errorf("%w: response attempt has no idempotency key", shared.ErrValidation)
	}
	if !a.State.Valid() {
		return fmt.Errorf("%w: response attempt has unknown state %q", shared.ErrValidation, a.State)
	}
	if !a.VerificationOutcome.Valid() {
		return fmt.Errorf("%w: response attempt has unknown verification outcome %q", shared.ErrValidation, a.VerificationOutcome)
	}
	return a.Target.Validate()
}

// Saga is the governed-response state machine for one action: its target, declared reversibility, current
// state, and the journal of execution attempts. Its safety-critical fields are UNEXPORTED so the only way
// to advance state is Transition — a caller cannot assign state = StateVerifiedSucceeded directly and
// fabricate a "contained" verdict that skipped the telemetry Verifying gate, nor swap the validated Target
// for an unvalidated one. Construct with NewSaga; read via the getters.
type Saga struct {
	actionID      shared.ID
	target        TargetFingerprint
	reversibility ReversibilityClass
	state         SagaState
	attempts      []ResponseAttempt
	seen          map[string]ResponseAttempt
}

// NewSaga starts a saga in StateProposed for a validated target + reversibility class.
func NewSaga(actionID shared.ID, target TargetFingerprint, reversibility ReversibilityClass) (*Saga, error) {
	if actionID.IsZero() {
		return nil, fmt.Errorf("%w: response saga has no action id", shared.ErrValidation)
	}
	if err := target.Validate(); err != nil {
		return nil, err
	}
	if !reversibility.Valid() {
		return nil, fmt.Errorf("%w: unknown reversibility class %q", shared.ErrValidation, reversibility)
	}
	return &Saga{actionID: actionID, target: target, reversibility: reversibility, state: StateProposed, seen: map[string]ResponseAttempt{}}, nil
}

// ActionID is the action this saga governs.
func (s *Saga) ActionID() shared.ID { return s.actionID }

// Target is the stable fingerprint of what the response acts on.
func (s *Saga) Target() TargetFingerprint { return s.target }

// Reversibility is the declared reversibility class of the response.
func (s *Saga) Reversibility() ReversibilityClass { return s.reversibility }

// State is the current saga state.
func (s *Saga) State() SagaState { return s.state }

// Transition advances the saga to a new state, rejecting an illegal transition (in particular
// CommandApplied -> VerifiedSucceeded, which must pass through Verifying).
func (s *Saga) Transition(to SagaState) error {
	if err := requireTransition(s.state, to); err != nil {
		return err
	}
	s.state = to
	return nil
}

// RecordAttempt journals an execution attempt, idempotently by IdempotencyKey: re-recording an identical
// attempt under a seen key is a no-op (so an at-least-once re-issue does not double-journal). The attempt
// must be valid and belong to this saga's action. A seen key re-used for a DIFFERENT attempt is rejected —
// silently masking it would hide a caller bug that could double-apply a distinct destructive action.
func (s *Saga) RecordAttempt(a ResponseAttempt) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if a.ActionID != s.actionID {
		return fmt.Errorf("%w: attempt belongs to %s, not %s", shared.ErrValidation, a.ActionID, s.actionID)
	}
	if s.seen == nil { // defend against a struct-literal-constructed saga bypassing NewSaga
		s.seen = map[string]ResponseAttempt{}
	}
	if prev, dup := s.seen[a.IdempotencyKey]; dup {
		if prev != a {
			return fmt.Errorf("%w: idempotency key %q re-used for a different attempt", shared.ErrValidation, a.IdempotencyKey)
		}
		return nil
	}
	s.seen[a.IdempotencyKey] = a
	s.attempts = append(s.attempts, a)
	return nil
}

// Attempts returns a copy of the journaled attempts in record order.
func (s *Saga) Attempts() []ResponseAttempt {
	out := make([]ResponseAttempt, len(s.attempts))
	copy(out, s.attempts)
	return out
}

// Contained reports whether the response reached a telemetry-verified success — StateVerifiedSucceeded, or
// StateCompleted (verified then finalized without a rollback). It is NEVER true for StateCommandApplied on
// its own: a command being issued is not proof the post-condition held.
func (s *Saga) Contained() bool {
	return s.state == StateVerifiedSucceeded || s.state == StateCompleted
}
