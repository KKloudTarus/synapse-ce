package response

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type responseFlight struct {
	actionID shared.ID
	tenantID shared.ID
	reversal bool
	cancel   context.CancelFunc
	done     chan struct{}
}

// registerFlightLocked installs the local kill-switch cancellation fence. The caller holds effectMu.
func (s *Service) registerFlightLocked(parent context.Context, tenantID, actionID shared.ID, reversal bool) (context.Context, func(), error) {
	direction := "apply"
	if reversal {
		direction = "revert"
	}
	key := responseFlightKey(tenantID, actionID, reversal)
	if _, exists := s.inFlight[key]; exists {
		return nil, nil, fmt.Errorf("%w: response %s already has an in-flight %s", shared.ErrConflict, actionID, direction)
	}
	ctx, cancel := context.WithCancel(parent)
	flight := &responseFlight{actionID: actionID, tenantID: tenantID, reversal: reversal, cancel: cancel, done: make(chan struct{})}
	s.inFlight[key] = flight
	finish := func() {
		s.effectMu.Lock()
		delete(s.inFlight, key)
		close(flight.done)
		s.effectMu.Unlock()
		cancel()
	}
	return ctx, finish, nil
}

// HaltResponses cancels every pending (admitted-but-not-yet-applied) response action for the tenant,
// exactly as the kill switch halts offensive work. It is the ResponseHalter the #418 kill switch drives,
// so its signature matches that seam. A single operator action, audited with the operator + reason.
func (s *Service) HaltResponses(ctx context.Context, tenantID shared.ID, actor, reason string) (int, error) {
	if strings.TrimSpace(actor) == "" || strings.TrimSpace(reason) == "" {
		return 0, fmt.Errorf("%w: a halt must name the operator and a reason", shared.ErrValidation)
	}
	ctx = shared.WithTenant(ctx, tenantID) // scope the halt to the tenant the kill switch named
	haltGeneration, haltIntent, haltDispatch, err := s.advanceHaltGeneration(ctx, tenantID, actor, reason)
	if err != nil {
		return 0, fmt.Errorf("advance response halt generation: %w", err)
	}
	s.effectMu.Lock()
	flights := make([]*responseFlight, 0)
	for _, flight := range s.inFlight {
		if flight.tenantID == tenantID {
			flight.cancel()
			flights = append(flights, flight)
		}
	}
	executorHaltCtx, cancelExecutorHalt := context.WithTimeout(ctx, 5*time.Second)
	executorHaltErr := s.deliverHaltDispatch(executorHaltCtx, haltDispatch)
	cancelExecutorHalt()
	pending, err := s.store.ListByState(ctx, StatePending)
	if err != nil {
		s.effectMu.Unlock()
		return 0, err
	}
	haltedActions := make(map[shared.ID]Record)
	haltedDirections := make(map[string]bool)
	failed := 0
	if executorHaltErr != nil {
		failed++
	}
	for _, rec := range pending {
		rec.State = StateCancelled
		rec.UpdatedAt = s.clock.Now().UTC()
		intent := responseAuditIntent(
			fmt.Sprintf("response-halt:v1:%s:%d:action:%s:cancelled", tenantID, haltGeneration, rec.ID),
			actor, "response.cancelled_by_halt", rec.ID.String(), rec.UpdatedAt,
			map[string]string{"reason": reason, "generation": fmt.Sprint(haltGeneration), "kind": string(rec.Action.Kind), "target": rec.Action.Target.String()},
		)
		transitioned, committed, transitionErr := s.store.TransitionWithAudit(ctx, rec, StatePending, intent)
		if transitionErr != nil || !transitioned {
			// A pending, production-changing action that could NOT be cancelled must not vanish from the
			// count and read as a clean halt — it is a hard failure the operator must see.
			failed++
			continue
		}
		if err := s.deliverResponseAudit(ctx, committed); err != nil {
			failed++
		}
		haltedActions[rec.ID] = rec
		haltedDirections[responseFlightKey(tenantID, rec.ID, false)] = true
	}
	active, err := s.store.ListAttemptsByState(ctx,
		responsesaga.StateIssued, responsesaga.StateClaimed, responsesaga.StateExecuting, responsesaga.StateOutcomeUnknown,
		responsesaga.StateCommandApplied, responsesaga.StateVerifying,
		responsesaga.StateRollbackRequested, responsesaga.StateRollingBack,
		responsesaga.StateRollbackVerifying, responsesaga.StateRollbackUnknown)
	if err != nil {
		s.effectMu.Unlock()
		return len(haltedActions), err
	}
	for _, attempt := range active {
		from := attempt.State
		to := responsesaga.StateCommandFailed
		alreadyAmbiguous := from == responsesaga.StateOutcomeUnknown ||
			from == responsesaga.StateRollbackVerifying || from == responsesaga.StateRollbackUnknown
		postEffectVerification := from == responsesaga.StateCommandApplied || from == responsesaga.StateVerifying
		if from == responsesaga.StateExecuting {
			to = responsesaga.StateOutcomeUnknown
		} else if from == responsesaga.StateRollingBack {
			to = responsesaga.StateRollbackUnknown
		} else if attempt.IsReversal {
			to = responsesaga.StateRollbackFailed
		}
		if !alreadyAmbiguous && !postEffectVerification {
			attempt.State = to
			attempt.CommandOutcome = "cancelled_by_kill_switch"
			operation := "apply"
			if attempt.IsReversal {
				operation = "revert"
			}
			intent := responseAuditIntent(
				fmt.Sprintf("response-halt:v1:%s:%d:attempt:%s:%s", tenantID, haltGeneration, attempt.IdempotencyKey, to),
				actor, "response.attempt_halted", attempt.ActionID.String(), s.clock.Now().UTC(),
				map[string]string{
					"reason": reason, "generation": fmt.Sprint(haltGeneration), "operation": operation,
					"from_state": string(from), "to_state": string(to), "attempt_idempotency_key": attempt.IdempotencyKey,
				},
			)
			stored, claimed, committed, claimErr := s.store.TransitionAttemptWithAudit(ctx, attempt, from, intent)
			if claimErr != nil {
				failed++
				continue
			}
			if !claimed && stored.State != to {
				failed++
				continue
			}
			if claimed {
				if err := s.deliverResponseAudit(ctx, committed); err != nil {
					failed++
				}
			}
		}
		rec, found, getErr := s.store.Get(ctx, attempt.ActionID)
		if getErr != nil || !found {
			failed++
			continue
		}
		haltedActions[attempt.ActionID] = rec
		haltedDirections[responseFlightKey(tenantID, attempt.ActionID, attempt.IsReversal)] = true
		if from == responsesaga.StateExecuting || from == responsesaga.StateRollingBack || alreadyAmbiguous || postEffectVerification {
			// Once dispatch began, cancellation is not proof that no effect occurred. The durable fence blocks
			// a false terminal projection, but halt remains failed until target-bound telemetry reconciles it.
			failed++
		}
	}
	s.effectMu.Unlock()
	// Fence the executor before attempting any external audit delivery. Both obligations are durable,
	// but a slow audit sink must never delay cancellation of a production-changing side effect.
	if err := s.deliverResponseAudit(ctx, haltIntent); err != nil {
		failed++
	}
	waitCtx, cancelWait := context.WithTimeout(ctx, 5*time.Second)
	defer cancelWait()
	for _, flight := range flights {
		select {
		case <-flight.done:
		case <-waitCtx.Done():
			return len(haltedActions), errors.Join(fmt.Errorf("%w: wait for halted response %s", shared.ErrSaturated, flight.actionID), waitCtx.Err())
		}
		rec, found, getErr := s.store.Get(ctx, flight.actionID)
		if getErr != nil || !found {
			failed++
			continue
		}
		haltedActions[flight.actionID] = rec
		haltedDirections[responseFlightKey(tenantID, flight.actionID, flight.reversal)] = true
		if flight.reversal {
			if rec.State != StateApplied {
				failed++
			}
		} else if rec.State != StateCancelled {
			failed++
		}
	}
	postEffect, err := s.store.ListAttemptsByState(ctx,
		responsesaga.StateCommandApplied, responsesaga.StateOutcomeUnknown, responsesaga.StateVerifying,
		responsesaga.StateVerifiedSucceeded, responsesaga.StateVerificationFailed,
		responsesaga.StateVerificationUnknown, responsesaga.StateTimedOut,
		responsesaga.StateRollbackVerifying, responsesaga.StateRollbackUnknown, responsesaga.StateRolledBack)
	if err != nil {
		return len(haltedActions), err
	}
	for _, attempt := range postEffect {
		if haltedDirections[responseFlightKey(tenantID, attempt.ActionID, attempt.IsReversal)] {
			failed++
		}
	}
	haltEvent := "response.halted"
	if failed > 0 {
		haltEvent = "response.halt_failed"
	}
	summaryIntent := responseAuditIntent(
		fmt.Sprintf("response-halt:v1:%s:%d:result", tenantID, haltGeneration), actor, haltEvent,
		tenantID.String(), s.clock.Now().UTC(), map[string]string{
			"reason": reason, "generation": fmt.Sprint(haltGeneration),
			"halted_actions": fmt.Sprint(len(haltedActions)), "failures": fmt.Sprint(failed),
		},
	)
	committedSummary, auditErr := s.store.EnqueueResponseAudit(ctx, summaryIntent)
	if auditErr == nil {
		auditErr = s.deliverResponseAudit(ctx, committedSummary)
	}
	if auditErr != nil {
		failed++
	}
	for _, rec := range haltedActions {
		intent := responseAuditIntent(
			fmt.Sprintf("response-halt:v1:%s:%d:%s:%s", tenantID, haltGeneration, rec.ID, haltEvent),
			actor, haltEvent, rec.ID.String(), s.clock.Now().UTC(),
			map[string]string{
				"reason": reason, "generation": fmt.Sprint(haltGeneration), "kind": string(rec.Action.Kind), "target": rec.Action.Target.String(),
			},
		)
		committed, auditErr := s.store.EnqueueResponseAudit(ctx, intent)
		if auditErr == nil {
			auditErr = s.deliverResponseAudit(ctx, committed)
		}
		if auditErr != nil {
			failed++
		}
	}
	halted := len(haltedActions)
	if failed > 0 {
		return halted, fmt.Errorf("%w: %d response cancellation operation(s) could not be proven safe", shared.ErrSaturated, failed)
	}
	return halted, nil
}

func (s *Service) advanceHaltGeneration(ctx context.Context, tenantID shared.ID, actor, reason string) (int64, ports.ResponseAuditIntent, ports.ResponseHaltDispatch, error) {
	for {
		current, err := s.haltWriter.CurrentHaltGeneration(ctx)
		if err != nil {
			return 0, ports.ResponseAuditIntent{}, ports.ResponseHaltDispatch{}, err
		}
		next := current + 1
		intent := responseAuditIntent(
			fmt.Sprintf("response-halt:v1:%s:%d:intent", tenantID, next), actor, "response.halt_intent",
			tenantID.String(), s.clock.Now().UTC(), map[string]string{"reason": reason, "generation": fmt.Sprint(next)},
		)
		generation, committed, dispatch, err := s.haltWriter.AdvanceHaltGenerationWithAudit(ctx, current, intent)
		if err == nil {
			return generation, committed, dispatch, nil
		}
		if !errors.Is(err, shared.ErrConflict) {
			return 0, ports.ResponseAuditIntent{}, ports.ResponseHaltDispatch{}, err
		}
		latest, readErr := s.haltWriter.CurrentHaltGeneration(ctx)
		if readErr != nil || latest == current {
			return 0, ports.ResponseAuditIntent{}, ports.ResponseHaltDispatch{}, errors.Join(err, readErr)
		}
	}
}
