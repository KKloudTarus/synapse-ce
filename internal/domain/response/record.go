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

// Record is the persisted state of a response action, including the approval that authorized it (sealed
// into the evidence chain by the admission gate).
type Record struct {
	ID                 shared.ID
	TenantID           shared.ID
	EngagementID       shared.ID
	Action             Action
	State              State
	ApprovedBy         string
	ApprovalEvidenceID shared.ID
	AppliedAt          time.Time
	UpdatedAt          time.Time
}
