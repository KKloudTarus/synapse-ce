package response

import (
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// State is the lifecycle of a response action.
type State string

const (
	StatePending   State = "pending"   // admitted-but-awaiting approval (the kill switch can cancel it)
	StateApplied   State = "applied"   // executed
	StateReverted  State = "reverted"  // its reversal was applied
	StateCancelled State = "cancelled" // halted by the kill switch before applying
	StateViolation State = "violation" // halted: actual effect exceeded the declared blast radius
)

// Valid reports whether s is a known state.
func (s State) Valid() bool {
	switch s {
	case StatePending, StateApplied, StateReverted, StateCancelled, StateViolation:
		return true
	default:
		return false
	}
}

// Verification is the post-condition axis of a response action: did the action's intended EFFECT
// actually take hold on the target, confirmed against telemetry? It is SEPARATE from State — a command
// that was applied (StateApplied) is NOT the same as an effect that was verified (#638). A kill whose
// syscall returned but whose process is still observed alive is VerificationFailed, not a success; a
// target with no covering telemetry is VerificationUnknown, never silently a success.
type Verification string

const (
	VerificationPending   Verification = ""          // not verified (no verifier wired, or verification not run)
	VerificationSucceeded Verification = "succeeded" // telemetry confirms the effect took hold
	VerificationFailed    Verification = "failed"    // the command applied but the effect is NOT present
	VerificationUnknown   Verification = "unknown"   // insufficient telemetry coverage to confirm or deny
)

// Valid reports whether v is a known verification outcome.
func (v Verification) Valid() bool {
	switch v {
	case VerificationPending, VerificationSucceeded, VerificationFailed, VerificationUnknown:
		return true
	default:
		return false
	}
}

// Record is the persisted state of a response action, including the approval that authorized it (sealed
// into the evidence chain by the admission gate).
type Record struct {
	ID                 shared.ID
	TenantID           shared.ID
	EngagementID       shared.ID
	Action             Action
	State              State
	Verification       Verification // post-condition: was the effect confirmed via telemetry? (#638)
	ApprovedBy         string
	ApprovalEvidenceID shared.ID
	AppliedAt          time.Time
	UpdatedAt          time.Time
}
