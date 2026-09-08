package response

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func (s *Service) recoverRolledBack(ctx context.Context, rec Record, attempt responsesaga.ResponseAttempt, transition bool) (Record, error) {
	if err := s.revalidatePersistedReceipt(ctx, rec, attempt); err != nil {
		return Record{}, fmt.Errorf("revalidate response %s rollback receipt: %w", rec.ID, err)
	}
	if transition {
		from := rec.State
		rec.State = StateReverted
		rec.UpdatedAt = s.clock.Now().UTC()
		if err := s.transition(ctx, rec, from); err != nil {
			return Record{}, fmt.Errorf("recover reverted response %s: %w", rec.ID, err)
		}
	}
	if err := s.recordOutcome(ctx, "response.reverted", attempt.DecidedBy, rec.Action, attempt, map[string]string{"reversal": string(rec.Action.Reversal.Kind)}); err != nil {
		return Record{}, fmt.Errorf("persist recovered response %s rollback audit: %w", rec.ID, err)
	}
	return rec, nil
}

// Revert applies an action's reversal. The reversal is itself ADMITTED (through the same gate) and
// AUDITED — a reversal is a first-class governed action, not an unchecked undo.
func (s *Service) Revert(ctx context.Context, actionID shared.ID, target engagement.Target, fingerprint responsesaga.TargetFingerprint, approver string) (Record, error) {
	tenantID, ok := shared.TenantFrom(ctx)
	if !ok {
		return Record{}, fmt.Errorf("%w: response rollback requires a tenant in context", shared.ErrValidation)
	}
	if err := s.ReconcileHaltDispatches(ctx); err != nil {
		return Record{}, fmt.Errorf("reconcile response halt fence before rollback: %w", err)
	}
	haltGeneration, err := s.store.CurrentHaltGeneration(ctx)
	if err != nil {
		return Record{}, fmt.Errorf("read response halt generation: %w", err)
	}
	rec, found, err := s.store.Get(ctx, actionID)
	if err != nil {
		return Record{}, err
	}
	if !found {
		return Record{}, fmt.Errorf("%w: no response action %s to revert", shared.ErrNotFound, actionID)
	}
	if rec.TenantID != tenantID {
		return Record{}, fmt.Errorf("%w: response action tenant does not match context", shared.ErrForbidden)
	}
	if isMachine(approver) {
		return Record{}, fmt.Errorf("%w: a reversal requires a human approver; %q is a machine identity", shared.ErrForbidden, approver)
	}
	if target != rec.AuthorizationTarget {
		return Record{}, fmt.Errorf("%w: reversal authorization target does not match the durable response binding", shared.ErrConflict)
	}
	if fingerprint != rec.TargetFingerprint {
		return Record{}, fmt.Errorf("%w: reversal target fingerprint does not match the durable response binding", shared.ErrConflict)
	}
	if target.Value != rec.Action.Target.String() {
		return Record{}, fmt.Errorf("%w: reversal target %q does not match the action target %q", shared.ErrForbidden, target.Value, rec.Action.Target)
	}
	if err := bindFingerprint(rec.Action, fingerprint); err != nil {
		return Record{}, err
	}
	if rec.State == StateReverted {
		candidate := newAttempt(rec.Action, fingerprint, true, responsesaga.StateRollbackRequested, haltGeneration, "", s.clock.Now().UTC())
		attempt, attemptFound, attemptErr := s.store.GetAttempt(ctx, candidate.IdempotencyKey)
		if attemptErr != nil {
			return Record{}, attemptErr
		}
		if !attemptFound || attempt.State != responsesaga.StateRolledBack {
			return Record{}, fmt.Errorf("%w: response %s is marked reverted without a verified rollback attempt", shared.ErrConflict, actionID)
		}
		if attempt.Target != fingerprint {
			return Record{}, fmt.Errorf("%w: response %s rollback fingerprint is immutable", shared.ErrConflict, actionID)
		}
		return s.recoverRolledBack(ctx, rec, attempt, false)
	}
	// Re-validate the stored action (and thus its reversal's argv-only / no-shell guard) before acting on
	// bytes read back from storage — defense in depth against a tampered row.
	if err := rec.Action.Validate(); err != nil {
		return Record{}, fmt.Errorf("stored response action %s is invalid: %w", actionID, err)
	}
	if s.verify == nil {
		return Record{}, fmt.Errorf("%w: response %s rollback requires a telemetry verifier", shared.ErrValidation, actionID)
	}
	applyCandidate := newAttempt(rec.Action, fingerprint, false, responsesaga.StateIssued, haltGeneration, "", s.clock.Now().UTC())
	applyAttempt, applyAttemptFound, err := s.store.GetAttempt(ctx, applyCandidate.IdempotencyKey)
	if err != nil {
		return Record{}, fmt.Errorf("load response %s original target fingerprint: %w", actionID, err)
	}
	if !applyAttemptFound || applyAttempt.Target != fingerprint {
		return Record{}, fmt.Errorf("%w: response %s rollback must use its original target fingerprint", shared.ErrConflict, actionID)
	}
	fingerprint = applyAttempt.Target
	parentState := rec.State
	switch rec.State {
	case StateApplied:
		// The command is durably known to have applied.
	case StatePending, StateCancelled:
		if applyAttempt.State != responsesaga.StateOutcomeUnknown && applyAttempt.State != responsesaga.StateRollbackRequested {
			return Record{}, fmt.Errorf("%w: response %s is %s and has no ambiguous effect to reverse", shared.ErrValidation, actionID, rec.State)
		}
		if applyAttempt.State == responsesaga.StateOutcomeUnknown {
			verification, verifierID, evidenceID, verificationErr := s.verifyEffect(ctx, rec.EngagementID, rec.Action, applyAttempt)
			if verification == VerificationPending {
				if s.attemptExpired(applyAttempt) {
					return s.expireAttempt(ctx, rec, applyAttempt, responsesaga.StateManualIntervention, "execution_outcome_deadline_exceeded")
				}
				return rec, verificationPendingError(actionID, "has no signed post-condition for rollback", verificationErr)
			}
			if verification != VerificationSucceeded {
				return Record{}, fmt.Errorf("%w: response %s ambiguous effect is not verified present for rollback", shared.ErrConflict, actionID)
			}
			applyAttempt.VerificationOutcome = responsesaga.VerificationSucceeded
			applyAttempt.VerifierID = verifierID
			applyAttempt.VerificationEvidenceID = evidenceID
			applyAttempt, err = s.transitionAttempt(ctx, applyAttempt, responsesaga.StateOutcomeUnknown, responsesaga.StateRollbackRequested)
			if err != nil {
				return Record{}, fmt.Errorf("persist response %s ambiguous-effect verification: %w", actionID, err)
			}
			if err := s.recordOutcome(ctx, "response.execution_requires_rollback", applyAttempt.DecidedBy, rec.Action, applyAttempt, map[string]string{"verification": string(verification)}); err != nil {
				return Record{}, fmt.Errorf("persist response %s rollback justification audit: %w", actionID, err)
			}
		}
		if applyAttempt.VerificationOutcome != responsesaga.VerificationSucceeded ||
			strings.TrimSpace(applyAttempt.VerifierID) == "" || applyAttempt.VerificationEvidenceID.IsZero() ||
			strings.EqualFold(strings.TrimSpace(applyAttempt.VerifierID), strings.TrimSpace(applyAttempt.ExecutorID)) {
			return Record{}, fmt.Errorf("%w: response %s rollback requirement lacks independent verification evidence", shared.ErrConflict, actionID)
		}
	default:
		return Record{}, fmt.Errorf("%w: response %s cannot be reverted from state %s", shared.ErrValidation, actionID, rec.State)
	}
	rollbackCandidate := newAttempt(rec.Action, fingerprint, true, responsesaga.StateRollbackRequested, haltGeneration, "", s.clock.Now().UTC())
	existingRollback, existingRollbackFound, err := s.store.GetAttempt(ctx, rollbackCandidate.IdempotencyKey)
	if err != nil {
		return Record{}, fmt.Errorf("load response %s rollback attempt: %w", actionID, err)
	}
	if existingRollbackFound {
		if existingRollback.Target != fingerprint {
			return Record{}, fmt.Errorf("%w: response %s rollback fingerprint is immutable", shared.ErrConflict, actionID)
		}
		switch existingRollback.State {
		case responsesaga.StateRollbackRequested:
			if s.attemptExpired(existingRollback) {
				return s.expireAttempt(ctx, rec, existingRollback, responsesaga.StateRollbackFailed, "rollback_dispatch_deadline_exceeded")
			}
			// The approved reversal was journaled but never claimed; resume below without reissuing any
			// attempt whose side-effect boundary may already have been crossed.
		case responsesaga.StateRollbackVerifying, responsesaga.StateRollbackUnknown:
			return s.finishRollback(ctx, ctx, rec, existingRollback)
		case responsesaga.StateRolledBack:
			return s.recoverRolledBack(ctx, rec, existingRollback, true)
		case responsesaga.StateRollbackFailed:
			return Record{}, fmt.Errorf("%w: response %s has a durable failed rollback attempt", shared.ErrConflict, actionID)
		default:
			return Record{}, fmt.Errorf("%w: response %s rollback attempt is %s and cannot be reissued", shared.ErrConflict, actionID, existingRollback.State)
		}
	}
	rev := rec.Action.Reversal
	p := agent.ProposedAction{
		ID: shared.ID("revert:" + actionID.String()), SessionID: shared.ID("response:" + actionID.String()), EngagementID: rec.EngagementID,
		Tool: "response." + string(rev.Kind), Action: "response." + string(rev.Kind),
		Target: target, Argv: rev.Argv, Risk: agent.RiskIntrusive, ProposedAt: s.clock.Now().UTC(),
		Rationale: "reverse response: " + rev.Description,
	}
	adm, err := s.admit.Admit(ctx, p, approver)
	if err != nil {
		if isPending(err) {
			if rec.ReversalRequestedBy != "" && !strings.EqualFold(strings.TrimSpace(rec.ReversalRequestedBy), strings.TrimSpace(approver)) {
				return Record{}, fmt.Errorf("%w: response %s reversal is already bound to another submitter", shared.ErrConflict, actionID)
			}
			rec.ReversalRequestedBy = strings.TrimSpace(approver)
			rec.UpdatedAt = s.clock.Now().UTC()
			if putErr := s.put(ctx, rec); putErr != nil {
				return Record{}, fmt.Errorf("persist pending response %s reversal: %w", actionID, putErr)
			}
			return rec, err
		}
		return Record{}, err
	}
	if rec.ReversalRequestedBy == "" {
		rec.ReversalRequestedBy = strings.TrimSpace(approver)
		rec.UpdatedAt = s.clock.Now().UTC()
		if err := s.put(ctx, rec); err != nil {
			return Record{}, fmt.Errorf("persist response %s reversal submitter: %w", actionID, err)
		}
	}
	if strings.EqualFold(strings.TrimSpace(rec.ReversalRequestedBy), strings.TrimSpace(adm.decidedBy)) {
		return Record{}, fmt.Errorf("%w: response reversal submitter cannot approve the same action", shared.ErrForbidden)
	}
	attempt := s.newAttempt(rec.Action, fingerprint, true, responsesaga.StateRollbackRequested, haltGeneration, adm.decidedBy, s.clock.Now().UTC())
	attempt.ExecutorID = strings.TrimSpace(s.exec.Identity())
	attempt.ExecutorAgentID, err = s.exec.ResolveAgent(ctx, tenantID, fingerprint)
	if err != nil {
		return Record{}, fmt.Errorf("resolve response %s rollback executor agent: %w", actionID, err)
	}
	if attempt.ExecutorAgentID.IsZero() {
		return Record{}, fmt.Errorf("%w: response %s rollback executor resolved no enrolled agent identity", shared.ErrForbidden, actionID)
	}
	if err := setVerificationChallenge(&attempt); err != nil {
		return Record{}, fmt.Errorf("generate response %s rollback verification challenge before dispatch: %w", actionID, err)
	}
	attempt, _, err = s.store.StartAttempt(ctx, attempt)
	if err != nil {
		return Record{}, fmt.Errorf("journal reversal %s before execution: %w", actionID, err)
	}
	switch attempt.State {
	case responsesaga.StateRolledBack:
		return s.recoverRolledBack(ctx, rec, attempt, true)
	case responsesaga.StateRollbackFailed:
		return Record{}, fmt.Errorf("%w: response %s has a durable failed rollback attempt", shared.ErrConflict, actionID)
	case responsesaga.StateRollbackVerifying, responsesaga.StateRollbackUnknown:
		return s.finishRollback(ctx, ctx, rec, attempt)
	case responsesaga.StateRollingBack:
		return Record{}, fmt.Errorf("%w: response %s rollback outcome is ambiguous and requires reconciliation", shared.ErrConflict, actionID)
	case responsesaga.StateRollbackRequested:
		if s.attemptExpired(attempt) {
			return s.expireAttempt(ctx, rec, attempt, responsesaga.StateRollbackFailed, "rollback_dispatch_deadline_exceeded")
		}
		// This delivery may claim the rollback after its audit intent is durable.
	default:
		return Record{}, fmt.Errorf("%w: response %s has unexpected rollback state %s", shared.ErrConflict, actionID, attempt.State)
	}
	if err := s.recordExecutionIntent(ctx, attempt.DecidedBy, rec.Action, attempt, adm.decidedBy); err != nil {
		return Record{}, fmt.Errorf("persist response %s reversal audit intent: %w", actionID, err)
	}
	claimAt := s.clock.Now().UTC()
	attempt, claimed, err := s.store.ClaimAttempt(ctx, attempt.IdempotencyKey, responsesaga.StateRollbackRequested, responsesaga.StateRollingBack, claimAt)
	if err != nil {
		return Record{}, fmt.Errorf("claim response %s rollback: %w", actionID, err)
	}
	if !claimed {
		if attempt.State == responsesaga.StateRollbackRequested && !claimAt.Before(attempt.DeadlineAt) {
			return s.expireAttempt(ctx, rec, attempt, responsesaga.StateRollbackFailed, "rollback_dispatch_deadline_exceeded")
		}
		if attempt.State == responsesaga.StateRolledBack {
			return s.recoverRolledBack(ctx, rec, attempt, true)
		}
		if attempt.State == responsesaga.StateRollbackVerifying || attempt.State == responsesaga.StateRollbackUnknown {
			return s.finishRollback(ctx, ctx, rec, attempt)
		}
		return Record{}, fmt.Errorf("%w: response %s rollback is already claimed and requires reconciliation", shared.ErrConflict, actionID)
	}
	s.effectMu.Lock()
	current, found, err := s.store.Get(ctx, actionID)
	if err != nil {
		s.effectMu.Unlock()
		return Record{}, fmt.Errorf("recheck response %s before rollback: %w", actionID, err)
	}
	if !found || current.State != parentState {
		s.effectMu.Unlock()
		attempt.CommandOutcome = "cancelled_before_execution"
		_, _ = s.transitionAttempt(ctx, attempt, responsesaga.StateRollingBack, responsesaga.StateRollbackFailed)
		return Record{}, fmt.Errorf("%w: response %s is no longer eligible for rollback", shared.ErrForbidden, actionID)
	}
	execCtx, finishFlight, err := s.registerFlightLocked(ctx, tenantID, actionID, true)
	s.effectMu.Unlock()
	if err != nil {
		return Record{}, err
	}
	defer finishFlight()
	execCtx, cancelDeadline := s.attemptContext(execCtx, attempt)
	defer cancelDeadline()
	if err := s.admit.Reauthorize(execCtx, adm); err != nil {
		attempt.CommandOutcome = "dispatch_reauthorization_refused"
		_, _ = s.transitionAttempt(ctx, attempt, responsesaga.StateRollingBack, responsesaga.StateRollbackFailed)
		return Record{}, fmt.Errorf("reauthorize response %s rollback at dispatch: %w", actionID, err)
	}
	if err := execCtx.Err(); err != nil {
		attempt.CommandOutcome = "cancelled_before_execution"
		_, _ = s.transitionAttempt(ctx, attempt, responsesaga.StateRollingBack, responsesaga.StateRollbackFailed)
		return Record{}, errors.Join(fmt.Errorf("%w: response %s rollback was halted before execution", shared.ErrForbidden, actionID), err)
	}
	currentAt := s.clock.Now().UTC()
	currentAttempt, err := s.store.AttemptStillCurrent(ctx, attempt.IdempotencyKey, responsesaga.StateRollingBack, currentAt)
	if err != nil {
		return Record{}, fmt.Errorf("recheck response %s rollback fence: %w", actionID, err)
	}
	if !currentAttempt {
		if !currentAt.Before(attempt.DeadlineAt) {
			return s.expireAttempt(ctx, rec, attempt, responsesaga.StateRollbackFailed, "rollback_dispatch_deadline_exceeded_after_claim")
		}
		return Record{}, fmt.Errorf("%w: response %s rollback was halted before execution", shared.ErrForbidden, actionID)
	}
	// The executed reversal argv is exactly the admitted payload (p.Argv above is rev.Argv).
	out, err := s.exec.Execute(execCtx, ExecRequest{
		TenantID: tenantID, EngagementID: rec.EngagementID, ActionID: actionID, AgentID: attempt.ExecutorAgentID, Action: cloneAction(rec.Action),
		Argv: slices.Clone(rev.Argv), Target: rec.Action.Target, Fingerprint: fingerprint,
		AuthorizationTarget: target,
		IdempotencyKey:      attempt.IdempotencyKey, Declared: rec.Action.BlastRadius, IsReversal: true,
		HaltGeneration: attempt.HaltGeneration, VerificationChallenge: attempt.VerificationChallenge,
		IssuedAt: attempt.At, DeadlineAt: attempt.DeadlineAt,
	})
	journalCtx, cancelJournal := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancelJournal()
	ctx = journalCtx
	if err == nil && out.EnforcedHaltGeneration != attempt.HaltGeneration {
		err = fmt.Errorf("%w: response executor did not enforce halt generation %d", shared.ErrForbidden, attempt.HaltGeneration)
	}
	if err != nil {
		attempt.CommandOutcome = "executor_error_outcome_unknown"
		attempt, journalErr := s.transitionAttempt(ctx, attempt, responsesaga.StateRollingBack, responsesaga.StateRollbackUnknown)
		if journalErr != nil {
			return Record{}, errors.Join(fmt.Errorf("execute reversal %s: %w", actionID, err), fmt.Errorf("persist failed rollback attempt: %w", journalErr))
		}
		execErr := fmt.Errorf("execute reversal %s: %w", actionID, err)
		if auditErr := s.recordOutcome(ctx, "response.rollback_outcome_unknown", attempt.DecidedBy, rec.Action, attempt, nil); auditErr != nil {
			return Record{}, errors.Join(execErr, fmt.Errorf("persist rollback failure audit: %w", auditErr))
		}
		return Record{}, execErr
	}
	if execCtx.Err() != nil || s.attemptExpired(attempt) {
		attempt.CommandOutcome = "completed_after_halt"
		if s.attemptExpired(attempt) || errors.Is(execCtx.Err(), context.DeadlineExceeded) {
			attempt.CommandOutcome = "completed_after_deadline"
		}
		attempt.ObservedRadius = out.ObservedRadius
		attempt.AffectedCount = out.AffectedCount
		attempt.AlreadyApplied = out.AlreadyApplied
		attempt, journalErr := s.transitionAttempt(ctx, attempt, responsesaga.StateRollingBack, responsesaga.StateRollbackUnknown)
		if journalErr != nil {
			return Record{}, fmt.Errorf("persist response %s ambiguous post-halt rollback: %w", actionID, journalErr)
		}
		haltErr := fmt.Errorf("%w: response %s rollback completed after kill-switch cancellation", shared.ErrForbidden, actionID)
		if auditErr := s.recordOutcome(ctx, "response.rollback_completed_after_halt", attempt.DecidedBy, rec.Action, attempt, nil); auditErr != nil {
			return Record{}, errors.Join(haltErr, fmt.Errorf("persist post-halt rollback audit: %w", auditErr))
		}
		return Record{}, haltErr
	}
	attempt.ObservedRadius = out.ObservedRadius
	attempt.AffectedCount = out.AffectedCount
	attempt.AlreadyApplied = out.AlreadyApplied
	if !attemptOutcomeInRadius(rec.Action.BlastRadius, attempt) {
		attempt.CommandOutcome = "blast_radius_violation"
		attempt, journalErr := s.transitionAttempt(ctx, attempt, responsesaga.StateRollingBack, responsesaga.StateRollbackUnknown)
		if journalErr != nil {
			return Record{}, fmt.Errorf("persist response %s rollback blast-radius violation: %w", actionID, journalErr)
		}
		meta := map[string]string{
			"declared": string(rec.Action.BlastRadius), "observed": string(out.ObservedRadius), "affected": fmt.Sprint(out.AffectedCount),
		}
		violationErr := fmt.Errorf("%w: response %s rollback exceeded its declared single-target radius (observed=%s affected=%d)", shared.ErrForbidden, actionID, out.ObservedRadius, out.AffectedCount)
		rec.State = StateViolation
		rec.UpdatedAt = s.clock.Now().UTC()
		intent := responseAuditIntent(
			attempt.IdempotencyKey+":response.reversal_blast_radius_violation", attempt.DecidedBy,
			"response.reversal_blast_radius_violation", rec.ID.String(), attempt.At, meta,
		)
		transitioned, committed, transitionErr := s.store.TransitionWithAudit(ctx, rec, parentState, intent)
		if transitionErr != nil {
			return rec, errors.Join(violationErr, fmt.Errorf("persist reversal violation %s: %w", actionID, transitionErr))
		}
		if !transitioned {
			return rec, errors.Join(violationErr, fmt.Errorf("%w: response %s state changed before reversal violation was recorded", shared.ErrConflict, actionID))
		}
		if auditErr := s.deliverResponseAudit(ctx, committed); auditErr != nil {
			return rec, errors.Join(violationErr, fmt.Errorf("deliver reversal blast-radius audit: %w", auditErr))
		}
		return rec, violationErr
	}
	if out.AlreadyApplied {
		attempt.CommandOutcome = "already_reverted"
	} else {
		attempt.CommandOutcome = "reversal_applied"
	}
	attempt, err = s.transitionAttempt(ctx, attempt, responsesaga.StateRollingBack, responsesaga.StateRollbackVerifying)
	if err != nil {
		return Record{}, fmt.Errorf("persist response %s rollback command outcome: %w", actionID, err)
	}
	return s.finishRollback(ctx, execCtx, rec, attempt)
}

func (s *Service) finishRollback(ctx, verifyCtx context.Context, rec Record, attempt responsesaga.ResponseAttempt) (Record, error) {
	if !attemptOutcomeInRadius(rec.Action.BlastRadius, attempt) {
		return Record{}, fmt.Errorf("%w: response %s rollback has no durable in-radius command outcome", shared.ErrConflict, rec.ID)
	}
	if attempt.State == responsesaga.StateRollbackUnknown {
		var err error
		attempt, err = s.transitionAttempt(ctx, attempt, responsesaga.StateRollbackUnknown, responsesaga.StateRollbackVerifying)
		if err != nil {
			return Record{}, fmt.Errorf("persist response %s rollback reconciliation start: %w", rec.ID, err)
		}
	}
	verification, verifierID, evidenceID, verificationErr := s.verifyEffect(verifyCtx, rec.EngagementID, rec.Action, attempt)
	if verification == VerificationPending {
		if s.attemptExpired(attempt) {
			return s.expireAttempt(ctx, rec, attempt, responsesaga.StateRollbackFailed, "rollback_verification_deadline_exceeded")
		}
		return rec, verificationPendingError(rec.ID, "rollback has no signed post-condition yet", verificationErr)
	}
	attempt.VerifierID = verifierID
	attempt.VerificationEvidenceID = evidenceID
	if verifyCtx.Err() != nil {
		attempt.VerificationOutcome = responseVerificationOutcome(verification)
		_, committed, journalErr := s.commitAttemptOutcome(ctx, attempt, responsesaga.StateRollbackVerifying, responsesaga.StateRollbackUnknown,
			"response.rollback_completed_after_halt", attempt.DecidedBy, rec.Action, nil)
		if journalErr != nil {
			return Record{}, fmt.Errorf("persist response %s post-halt rollback verification: %w", rec.ID, journalErr)
		}
		haltErr := fmt.Errorf("%w: response %s rollback verification was interrupted by the kill switch", shared.ErrForbidden, rec.ID)
		if auditErr := s.deliverResponseAudit(ctx, committed); auditErr != nil {
			return Record{}, errors.Join(haltErr, fmt.Errorf("persist post-halt rollback audit: %w", auditErr))
		}
		return Record{}, haltErr
	}
	if verification != VerificationSucceeded {
		attempt.VerificationOutcome = responseVerificationOutcome(verification)
		event := "response.rollback_verification_failed"
		if verification == VerificationUnknown {
			event = "response.rollback_verification_unknown"
		}
		_, committed, journalErr := s.commitAttemptOutcome(ctx, attempt, responsesaga.StateRollbackVerifying, responsesaga.StateRollbackFailed,
			event, attempt.DecidedBy, rec.Action, map[string]string{"verification": string(verification)})
		if journalErr != nil {
			return Record{}, fmt.Errorf("persist response %s rollback verification failure: %w", rec.ID, journalErr)
		}
		from := rec.State
		rec.State = StateViolation
		rec.UpdatedAt = s.clock.Now().UTC()
		if err := s.transition(ctx, rec, from); err != nil {
			return rec, fmt.Errorf("project response %s failed rollback: %w", rec.ID, err)
		}
		verificationErr := fmt.Errorf("%w: response %s rollback state was not verified (outcome=%s)", shared.ErrForbidden, rec.ID, verification)
		if auditErr := s.deliverResponseAudit(ctx, committed); auditErr != nil {
			return Record{}, errors.Join(verificationErr, fmt.Errorf("persist rollback verification audit: %w", auditErr))
		}
		return rec, verificationErr
	}
	attempt.VerificationOutcome = responsesaga.VerificationSucceeded
	attempt, committed, err := s.commitAttemptOutcome(ctx, attempt, responsesaga.StateRollbackVerifying, responsesaga.StateRolledBack,
		"response.reverted", attempt.DecidedBy, rec.Action, map[string]string{"reversal": string(rec.Action.Reversal.Kind)})
	if err != nil {
		return Record{}, fmt.Errorf("persist response %s rollback outcome after execution: %w", rec.ID, err)
	}
	from := rec.State
	rec.State = StateReverted
	rec.UpdatedAt = s.clock.Now().UTC()
	if err := s.transition(ctx, rec, from); err != nil {
		return Record{}, err
	}
	if err := s.deliverResponseAudit(ctx, committed); err != nil {
		return Record{}, fmt.Errorf("persist response %s rollback audit: %w", rec.ID, err)
	}
	return rec, nil
}
