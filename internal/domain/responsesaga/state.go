// Package responsesaga is the pure-domain state machine for a GOVERNED response action's full lifecycle
// (Phase C, C6 #680) — the distributed saga from proposal through approval, agent execution, and a
// TELEMETRY-VERIFIED post-condition to an optional rollback. Its defining discipline: CommandApplied is
// NOT VerifiedSucceeded — a successful `kill` syscall is not proof of containment — so a response can only
// reach StateVerifiedSucceeded by passing through StateVerifying (a telemetry check), never directly from
// StateCommandApplied. Targets are identified by a stable TargetFingerprint (never a bare PID), and each
// at-least-once execution attempt is journaled with an idempotency key so a re-issue cannot double-apply.
//
// This package owns the saga model + transition rules; the agent-side execution, the live
// telemetry-verification, and the wiring onto the incident (C1 ResponseRequested/ResponseVerified events)
// are composed on top of it.
package responsesaga

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// SagaState is a stage in the governed-response lifecycle.
type SagaState string

const (
	StateProposed            SagaState = "proposed"
	StateAwaitingApproval    SagaState = "awaiting_approval"
	StateApproved            SagaState = "approved"
	StateRejected            SagaState = "rejected"
	StateIssued              SagaState = "issued"
	StateClaimed             SagaState = "claimed"
	StateExecuting           SagaState = "executing"
	StateCommandApplied      SagaState = "command_applied"
	StateCommandFailed       SagaState = "command_failed"
	StateVerifying           SagaState = "verifying"
	StateVerifiedSucceeded   SagaState = "verified_succeeded"
	StateVerificationFailed  SagaState = "verification_failed"
	StateVerificationUnknown SagaState = "verification_unknown"
	StateTimedOut            SagaState = "timed_out"
	StateRollbackRequested   SagaState = "rollback_requested"
	StateRollingBack         SagaState = "rolling_back"
	StateRolledBack          SagaState = "rolled_back"
	StateRollbackFailed      SagaState = "rollback_failed"
	// StateCompleted is the terminal state of a telemetry-verified response that was accepted and NOT
	// reverted, so a contained response reaches a real end state — a worker keying "done" off Terminal()
	// would otherwise loop forever on a StateVerifiedSucceeded whose only other exit is a rollback.
	StateCompleted SagaState = "completed"
)

// transitions is the legal state graph. Crucially, StateVerifiedSucceeded is reachable ONLY from
// StateVerifying — never from StateCommandApplied — encoding "command applied != post-condition verified".
// Every post-command verification outcome (failed/unknown/timed-out) can request a conservative rollback.
var transitions = map[SagaState][]SagaState{
	StateProposed:            {StateAwaitingApproval, StateRejected},
	StateAwaitingApproval:    {StateApproved, StateRejected},
	StateApproved:            {StateIssued},
	StateRejected:            {},
	StateIssued:              {StateClaimed},
	StateClaimed:             {StateExecuting},
	StateExecuting:           {StateCommandApplied, StateCommandFailed},
	StateCommandApplied:      {StateVerifying},
	StateCommandFailed:       {StateRollbackRequested},
	StateVerifying:           {StateVerifiedSucceeded, StateVerificationFailed, StateVerificationUnknown, StateTimedOut},
	StateVerifiedSucceeded:   {StateCompleted, StateRollbackRequested},
	StateVerificationFailed:  {StateRollbackRequested},
	StateVerificationUnknown: {StateRollbackRequested},
	StateTimedOut:            {StateRollbackRequested},
	StateRollbackRequested:   {StateRollingBack},
	StateRollingBack:         {StateRolledBack, StateRollbackFailed},
	StateCompleted:           {},
	StateRolledBack:          {},
	StateRollbackFailed:      {},
}

// Valid reports whether s is a known state.
func (s SagaState) Valid() bool {
	_, ok := transitions[s]
	return ok
}

// Terminal reports whether s has no outgoing transitions.
func (s SagaState) Terminal() bool {
	next, ok := transitions[s]
	return ok && len(next) == 0
}

// CanTransition reports whether from -> to is a legal saga transition.
func CanTransition(from, to SagaState) bool {
	for _, n := range transitions[from] {
		if n == to {
			return true
		}
	}
	return false
}

func requireTransition(from, to SagaState) error {
	if !to.Valid() {
		return fmt.Errorf("%w: unknown response saga state %q", shared.ErrValidation, to)
	}
	if !CanTransition(from, to) {
		return fmt.Errorf("%w: illegal response saga transition %s -> %s", shared.ErrValidation, from, to)
	}
	return nil
}
