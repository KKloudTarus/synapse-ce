// Package writeintent is the pure lifecycle shared by ticketing and documentation publishing.
// A remote write with an unknown outcome is NEVER blindly repeated.
package writeintent

import (
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type State string

const (
	Pending   State = "pending"
	InFlight  State = "in_flight"
	Done      State = "done"
	Failed    State = "failed"
	Uncertain State = "uncertain"
)

func (s State) Valid() bool {
	switch s {
	case Pending, InFlight, Done, Failed, Uncertain:
		return true
	}
	return false
}
func (s State) Terminal() bool { return s == Done }

// Event names describe evidence, not arbitrary assignments of a desired state.
// ReconcileAbsent is legal only after a provider search has proven zero matching markers;
// ReconcileFound is legal only after exactly one matching remote object is identified.
// ReconcileMultiple records that a provider search found more than one marker match.
type Event string

const (
	Claim             Event = "claim"
	Acknowledge       Event = "acknowledge"
	Reject            Event = "reject"
	Ambiguous         Event = "ambiguous"
	LeaseExpired      Event = "lease_expired"
	RetryFailed       Event = "retry_failed"
	ReconcileAbsent   Event = "reconcile_absent"
	ReconcileFound    Event = "reconcile_found"
	ReconcileMultiple Event = "reconcile_multiple"
)

func Next(from State, event Event) (State, error) {
	var to State
	switch {
	case from == Pending && event == Claim:
		to = InFlight
	case from == InFlight && event == Acknowledge:
		to = Done
	case from == InFlight && event == Reject:
		// Reject is only for a definite provider refusal, not a connection error.
		to = Failed
	case from == InFlight && (event == Ambiguous || event == LeaseExpired):
		to = Uncertain
	case from == Failed && event == RetryFailed:
		to = Pending
	case from == Uncertain && event == ReconcileAbsent:
		to = Pending
	case from == Uncertain && event == ReconcileFound:
		to = Done
	case from == Uncertain && event == ReconcileMultiple:
		to = Uncertain
	default:
		return "", fmt.Errorf("%w: invalid write intent transition", shared.ErrConflict)
	}
	return to, nil
}
