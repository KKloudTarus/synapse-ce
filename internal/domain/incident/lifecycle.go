package incident

import "errors"

// ErrInvalidTransition marks a lifecycle move that the Incident state graph forbids.
var ErrInvalidTransition = errors.New("invalid incident transition")

// State is the operational lifecycle of an Incident. It is intentionally independent from Disposition:
// an incident may be closed while still unknown, or remain under investigation after an analyst marks it
// true-positive.
type State string

const (
	StateNew           State = "new"
	StateOpen          State = "open"
	StateTriaged       State = "triaged"
	StateInvestigating State = "investigating"
	StateContained     State = "contained"
	StateRemediated    State = "remediated"
	StateResolved      State = "resolved"
	StateClosed        State = "closed"
	StateReopened      State = "reopened"
)

// Valid reports whether s belongs to the Phase-C lifecycle vocabulary.
func (s State) Valid() bool {
	switch s {
	case StateNew, StateOpen, StateTriaged, StateInvestigating, StateContained,
		StateRemediated, StateResolved, StateClosed, StateReopened:
		return true
	default:
		return false
	}
}

// CanTransitionTo enforces forward lifecycle progress. A resolved or closed Incident can only move
// backwards through the explicit reopened state, preventing a replay or stale writer from silently
// erasing terminal history.
func (s State) CanTransitionTo(to State) bool {
	if !s.Valid() || !to.Valid() || s == to {
		return false
	}
	switch s {
	case StateNew:
		return to == StateOpen
	case StateOpen:
		return to == StateTriaged || to == StateInvestigating || to == StateContained ||
			to == StateResolved || to == StateClosed
	case StateTriaged:
		return to == StateInvestigating || to == StateContained || to == StateResolved || to == StateClosed
	case StateInvestigating:
		return to == StateContained || to == StateRemediated || to == StateResolved || to == StateClosed
	case StateContained:
		return to == StateInvestigating || to == StateRemediated || to == StateResolved || to == StateClosed
	case StateRemediated:
		return to == StateResolved || to == StateClosed
	case StateResolved, StateClosed:
		return to == StateReopened
	case StateReopened:
		return to == StateOpen || to == StateInvestigating
	default:
		return false
	}
}

// Disposition is the analyst's factual classification of an Incident. It never drives State implicitly;
// every lifecycle change remains a separate append-only event.
type Disposition string

const (
	DispositionUnknown        Disposition = "unknown"
	DispositionTruePositive   Disposition = "true_positive"
	DispositionBenignPositive Disposition = "benign_positive"
	DispositionFalsePositive  Disposition = "false_positive"
	DispositionDuplicate      Disposition = "duplicate"
	DispositionTest           Disposition = "test"
)

// Valid reports whether d belongs to the Phase-C analyst-disposition vocabulary.
func (d Disposition) Valid() bool {
	switch d {
	case DispositionUnknown, DispositionTruePositive, DispositionBenignPositive,
		DispositionFalsePositive, DispositionDuplicate, DispositionTest:
		return true
	default:
		return false
	}
}
