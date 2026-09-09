package response

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func (s *Service) reconcileUnknownApply(ctx context.Context, rec Record, attempt responsesaga.ResponseAttempt) (Record, error) {
	if s.verify == nil {
		return Record{}, fmt.Errorf("%w: response %s execution outcome requires telemetry reconciliation", shared.ErrConflict, rec.ID)
	}
	verification, verifierID, evidenceID, verificationErr := s.verifyEffect(ctx, rec.EngagementID, rec.Action, attempt)
	if verification == VerificationPending {
		if s.attemptExpired(attempt) {
			return s.expireAttempt(ctx, rec, attempt, responsesaga.StateManualIntervention, "execution_outcome_deadline_exceeded")
		}
		return rec, verificationPendingError(rec.ID, "has no signed post-condition yet", verificationErr)
	}
	attempt.VerifierID = verifierID
	attempt.VerificationEvidenceID = evidenceID
	attempt.VerificationOutcome = responseVerificationOutcome(verification)
	if verification == VerificationFailed {
		attempt.CommandOutcome = "telemetry_confirmed_not_applied"
		attempt, err := s.transitionAttempt(ctx, attempt, responsesaga.StateOutcomeUnknown, responsesaga.StateCommandFailed)
		if err != nil {
			return Record{}, fmt.Errorf("persist response %s reconciled outcome: %w", rec.ID, err)
		}
		if err := s.recordOutcome(ctx, "response.execution_failed", attempt.DecidedBy, rec.Action, attempt, map[string]string{"verification": string(verification)}); err != nil {
			return Record{}, fmt.Errorf("persist response %s reconciled failure audit: %w", rec.ID, err)
		}
		return Record{}, fmt.Errorf("%w: telemetry confirmed response %s did not take effect", shared.ErrConflict, rec.ID)
	}
	event := "response.execution_outcome_unknown"
	if verification == VerificationSucceeded {
		event = "response.execution_requires_rollback"
		updatedAttempt, err := s.transitionAttempt(ctx, attempt, responsesaga.StateOutcomeUnknown, responsesaga.StateRollbackRequested)
		if err != nil {
			return Record{}, fmt.Errorf("persist response %s rollback requirement: %w", rec.ID, err)
		}
		attempt = updatedAttempt
	}
	if err := s.recordOutcome(ctx, event, attempt.DecidedBy, rec.Action, attempt, map[string]string{"verification": string(verification)}); err != nil {
		return Record{}, fmt.Errorf("persist response %s reconciliation audit: %w", rec.ID, err)
	}
	return Record{}, fmt.Errorf("%w: response %s execution outcome remains unsafe and requires governed rollback", shared.ErrConflict, rec.ID)
}

// ReconcileVerifications repairs every nonterminal execution stage without reissuing a command whose
// side-effect boundary may have been crossed. Missing evidence is retryable only until the durable deadline.
func (s *Service) ReconcileVerifications(ctx context.Context) error {
	attempts, err := s.store.ListAttemptsByState(ctx,
		responsesaga.StateIssued,
		responsesaga.StateClaimed,
		responsesaga.StateExecuting,
		responsesaga.StateCommandApplied,
		responsesaga.StateCommandFailed,
		responsesaga.StateVerifying,
		responsesaga.StateVerifiedSucceeded,
		responsesaga.StateVerificationFailed,
		responsesaga.StateVerificationUnknown,
		responsesaga.StateTimedOut,
		responsesaga.StateOutcomeUnknown,
		responsesaga.StateManualIntervention,
		responsesaga.StateRollbackRequested,
		responsesaga.StateRollingBack,
		responsesaga.StateRollbackVerifying,
		responsesaga.StateRollbackUnknown,
		responsesaga.StateRolledBack,
		responsesaga.StateRollbackFailed,
	)
	if err != nil {
		return fmt.Errorf("list pending response verifications: %w", err)
	}
	var errs []error
	for _, attempt := range attempts {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		rec, found, err := s.store.Get(ctx, attempt.ActionID)
		if err != nil {
			errs = append(errs, fmt.Errorf("load response %s for verification reconciliation: %w", attempt.ActionID, err))
			continue
		}
		if !found {
			errs = append(errs, fmt.Errorf("%w: response %s for pending attempt", shared.ErrNotFound, attempt.ActionID))
			continue
		}
		expired := !s.clock.Now().UTC().Before(s.attemptDeadline(attempt))
		switch attempt.State {
		case responsesaga.StateIssued:
			if expired {
				err = s.terminalizeAttempt(ctx, rec, attempt, responsesaga.StateCommandFailed, "dispatch_deadline_exceeded")
			} else {
				_, err = s.Apply(ctx, rec.EngagementID, rec.Action, rec.AuthorizationTarget, rec.TargetFingerprint, attempt.DecidedBy)
			}
		case responsesaga.StateClaimed, responsesaga.StateExecuting:
			if expired {
				err = s.terminalizeAttempt(ctx, rec, attempt, responsesaga.StateManualIntervention, "execution_outcome_deadline_exceeded")
			}
		case responsesaga.StateCommandApplied:
			if expired {
				err = s.terminalizeAttempt(ctx, rec, attempt, responsesaga.StateTimedOut, "verification_deadline_exceeded")
			} else {
				verifyCtx, cancel := s.verificationContext(ctx, attempt)
				_, err = s.finishApplied(ctx, verifyCtx, rec, attempt, rec.ApprovedBy)
				cancel()
			}
		case responsesaga.StateVerifying:
			if expired {
				err = s.terminalizeAttempt(ctx, rec, attempt, responsesaga.StateTimedOut, "verification_deadline_exceeded")
			} else {
				verifyCtx, cancel := s.verificationContext(ctx, attempt)
				_, err = s.finishApplied(ctx, verifyCtx, rec, attempt, rec.ApprovedBy)
				cancel()
			}
		case responsesaga.StateOutcomeUnknown:
			if expired {
				err = s.terminalizeAttempt(ctx, rec, attempt, responsesaga.StateManualIntervention, "execution_outcome_deadline_exceeded")
			} else {
				verifyCtx, cancel := s.verificationContext(ctx, attempt)
				_, err = s.reconcileUnknownApply(verifyCtx, rec, attempt)
				cancel()
			}
		case responsesaga.StateVerifiedSucceeded, responsesaga.StateVerificationFailed, responsesaga.StateVerificationUnknown:
			if !applyProjectionAligned(rec, attempt) {
				var projected Record
				projected, err = s.finishApplied(ctx, ctx, rec, attempt, rec.ApprovedBy)
				if projected.ID == rec.ID && applyProjectionAligned(projected, attempt) {
					err = nil
				}
			}
		case responsesaga.StateRollbackRequested:
			if attempt.IsReversal {
				if expired {
					err = s.terminalizeAttempt(ctx, rec, attempt, responsesaga.StateRollbackFailed, "rollback_dispatch_deadline_exceeded")
				} else {
					_, err = s.Revert(ctx, rec.ID, rec.AuthorizationTarget, rec.TargetFingerprint, attempt.DecidedBy)
				}
			} else if expired {
				err = s.terminalizeAttempt(ctx, rec, attempt, responsesaga.StateManualIntervention, "governed_rollback_not_started_before_deadline")
			}
		case responsesaga.StateRollingBack:
			if expired {
				err = s.terminalizeAttempt(ctx, rec, attempt, responsesaga.StateRollbackFailed, "rollback_outcome_deadline_exceeded")
			}
		case responsesaga.StateRollbackVerifying, responsesaga.StateRollbackUnknown:
			if expired {
				err = s.terminalizeAttempt(ctx, rec, attempt, responsesaga.StateRollbackFailed, "rollback_verification_deadline_exceeded")
			} else {
				verifyCtx, cancel := s.verificationContext(ctx, attempt)
				_, err = s.finishRollback(ctx, verifyCtx, rec, attempt)
				cancel()
			}
		case responsesaga.StateRolledBack:
			if rec.State != StateReverted {
				_, err = s.recoverRolledBack(ctx, rec, attempt, true)
			}
		case responsesaga.StateCommandFailed, responsesaga.StateTimedOut,
			responsesaga.StateManualIntervention, responsesaga.StateRollbackFailed:
			err = s.projectTerminalAttempt(ctx, rec, attempt)
		}
		if err != nil && !onlyVerificationPending(err) {
			errs = append(errs, fmt.Errorf("reconcile response verification %s: %w", attempt.IdempotencyKey, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Service) attemptDeadline(attempt responsesaga.ResponseAttempt) time.Time {
	if !attempt.DeadlineAt.IsZero() {
		return attempt.DeadlineAt.UTC()
	}
	if attempt.At.IsZero() {
		return s.clock.Now().UTC()
	}
	return attempt.At.UTC().Add(s.verificationTimeout)
}

func (s *Service) attemptExpired(attempt responsesaga.ResponseAttempt) bool {
	return !s.clock.Now().UTC().Before(s.attemptDeadline(attempt))
}

func (s *Service) attemptContext(ctx context.Context, attempt responsesaga.ResponseAttempt) (context.Context, context.CancelFunc) {
	remaining := s.attemptDeadline(attempt).Sub(s.clock.Now().UTC())
	if remaining <= 0 {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		return cancelled, func() {}
	}
	return context.WithTimeout(ctx, remaining)
}

func (s *Service) verificationContext(ctx context.Context, attempt responsesaga.ResponseAttempt) (context.Context, context.CancelFunc) {
	timeout := verificationCallTimeout
	remaining := s.attemptDeadline(attempt).Sub(s.clock.Now().UTC())
	if remaining <= 0 {
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		return cancelled, func() {}
	}
	if remaining < timeout {
		timeout = remaining
	}
	return context.WithTimeout(ctx, timeout)
}

func verificationPendingError(actionID shared.ID, detail string, cause error) error {
	if cause != nil && !errors.Is(cause, ErrVerificationPending) {
		return &verificationPendingFailure{actionID: actionID, detail: detail, cause: cause}
	}
	return fmt.Errorf("%w: response %s %s", ErrVerificationPending, actionID, detail)
}

func onlyVerificationPending(err error) bool {
	if !errors.Is(err, ErrVerificationPending) {
		return false
	}
	var operational *verificationPendingFailure
	return !errors.As(err, &operational)
}

func (s *Service) expireAttempt(ctx context.Context, rec Record, attempt responsesaga.ResponseAttempt, to responsesaga.SagaState, reason string) (Record, error) {
	transitionErr := s.terminalizeAttempt(ctx, rec, attempt, to, reason)
	stored, found, loadErr := s.store.Get(ctx, rec.ID)
	if loadErr == nil && !found {
		loadErr = fmt.Errorf("%w: response %s after deadline transition", shared.ErrNotFound, rec.ID)
	}
	if !found {
		stored = rec
	}
	return stored, errors.Join(
		fmt.Errorf("%w: response %s", ErrAttemptDeadlineExceeded, rec.ID),
		transitionErr,
		loadErr,
	)
}

func (s *Service) terminalizeAttempt(ctx context.Context, rec Record, attempt responsesaga.ResponseAttempt, to responsesaga.SagaState, reason string) error {
	from := attempt.State
	attempt.State = to
	attempt.TerminalReason = reason
	if attempt.DeadlineAt.IsZero() {
		attempt.DeadlineAt = s.attemptDeadline(attempt)
	}
	switch to {
	case responsesaga.StateTimedOut, responsesaga.StateRollbackFailed:
		attempt.VerificationOutcome = responsesaga.VerificationTimedOut
	case responsesaga.StateManualIntervention:
		attempt.VerificationOutcome = responsesaga.VerificationUnknown
	}
	actor := strings.TrimSpace(attempt.DecidedBy)
	if actor == "" {
		actor = "system"
	}
	intent := responseAuditIntent(
		attempt.IdempotencyKey+":terminal:"+string(to), actor, "response.attempt_terminal",
		attempt.ActionID.String(), attempt.DeadlineAt,
		map[string]string{"from_state": string(from), "to_state": string(to), "reason": reason},
	)
	stored, transitioned, committed, err := s.store.TransitionAttemptWithAudit(ctx, attempt, from, intent)
	if err != nil {
		return err
	}
	if !transitioned {
		if stored.State != to {
			return fmt.Errorf("%w: response attempt %s changed from %s to %s", shared.ErrConflict, attempt.IdempotencyKey, from, stored.State)
		}
		attempt = stored
	}
	projectionErr := s.projectTerminalAttempt(ctx, rec, attempt)
	var auditErr error
	if transitioned {
		auditErr = s.deliverResponseAudit(ctx, committed)
	}
	return errors.Join(projectionErr, auditErr)
}

func (s *Service) projectTerminalAttempt(ctx context.Context, rec Record, attempt responsesaga.ResponseAttempt) error {
	desiredState := rec.State
	desiredVerification := rec.Verification
	switch attempt.State {
	case responsesaga.StateCommandFailed:
		if rec.State == StatePending {
			desiredState = StateCancelled
		}
	case responsesaga.StateTimedOut:
		if attempt.IsReversal {
			return fmt.Errorf("%w: reversal attempt cannot end in apply verification timeout", shared.ErrValidation)
		}
		if rec.State == StatePending {
			desiredState = StateApplied
		}
		desiredVerification = VerificationUnknown
	case responsesaga.StateManualIntervention:
		desiredState = StateViolation
		if !attempt.IsReversal {
			desiredVerification = VerificationUnknown
		}
	case responsesaga.StateRollbackFailed:
		desiredState = StateViolation
	default:
		return fmt.Errorf("%w: attempt %s is not a terminal projection state", shared.ErrValidation, attempt.IdempotencyKey)
	}
	if rec.State == StateReverted || (rec.State == desiredState && rec.Verification == desiredVerification) {
		return nil
	}
	from := rec.State
	rec.State = desiredState
	rec.Verification = desiredVerification
	rec.UpdatedAt = s.clock.Now().UTC()
	if desiredState == StateApplied && rec.AppliedAt.IsZero() {
		rec.AppliedAt = rec.UpdatedAt
	}
	if err := s.transition(ctx, rec, from); err != nil {
		return fmt.Errorf("project terminal response attempt %s: %w", attempt.IdempotencyKey, err)
	}
	return nil
}

func applyProjectionAligned(rec Record, attempt responsesaga.ResponseAttempt) bool {
	if rec.State == StateReverted || rec.State == StateViolation {
		return true
	}
	if rec.State != StateApplied {
		return false
	}
	switch attempt.State {
	case responsesaga.StateVerifiedSucceeded:
		return rec.Verification == VerificationSucceeded
	case responsesaga.StateVerificationFailed:
		return rec.Verification == VerificationFailed
	case responsesaga.StateVerificationUnknown:
		return rec.Verification == VerificationUnknown
	default:
		return false
	}
}

// ReconcilePending repairs executor fences before verification and audit delivery so safety takes precedence.
func (s *Service) ReconcilePending(ctx context.Context) error {
	haltErr := s.ReconcileHaltDispatches(ctx)
	verificationErr := s.ReconcileVerifications(ctx)
	auditErr := s.ReconcileAudits(ctx)
	return errors.Join(haltErr, verificationErr, auditErr)
}
