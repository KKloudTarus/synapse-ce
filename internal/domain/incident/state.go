// Package incident is the pure-domain, event-sourced Incident primitive for Phase C of the EDR data plane
// (#594, C1 #675). Its central discipline: an incident's State (where it is in the response workflow),
// its Disposition (the analyst's verdict), and its risk (how dangerous / how sure / how well-observed)
// are FOUR DIFFERENT THINGS and never conflated. An incident is an ordered log of IncidentEvents folded
// into a mutable projection, so every change is attributable, replayable, and diffable — no field is set
// except through an event.
package incident

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// State is where an incident sits in the response workflow. It is independent of Disposition (the verdict)
// and of risk.
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

// allowedTransitions is the legal state graph. A StatusChanged event to a state not reachable from the
// current one fails the fold closed, so an incident's history can never contain an impossible workflow.
var allowedTransitions = map[State][]State{
	StateNew:           {StateOpen, StateTriaged, StateInvestigating, StateClosed},
	StateOpen:          {StateTriaged, StateInvestigating, StateContained, StateClosed},
	StateTriaged:       {StateInvestigating, StateContained, StateResolved, StateClosed},
	StateInvestigating: {StateContained, StateRemediated, StateResolved, StateClosed},
	StateContained:     {StateInvestigating, StateRemediated, StateResolved, StateClosed},
	StateRemediated:    {StateResolved, StateClosed},
	StateResolved:      {StateClosed, StateReopened},
	StateClosed:        {StateReopened},
	StateReopened:      {StateOpen, StateTriaged, StateInvestigating, StateClosed},
}

// Valid reports whether s is a known state.
func (s State) Valid() bool {
	_, ok := allowedTransitions[s]
	return ok
}

// CanTransition reports whether from -> to is a legal workflow transition.
func CanTransition(from, to State) bool {
	for _, n := range allowedTransitions[from] {
		if n == to {
			return true
		}
	}
	return false
}

// requireTransition returns an error if from -> to is not legal.
func requireTransition(from, to State) error {
	if !to.Valid() {
		return fmt.Errorf("%w: unknown incident state %q", shared.ErrValidation, to)
	}
	if !CanTransition(from, to) {
		return fmt.Errorf("%w: illegal incident transition %s -> %s", shared.ErrValidation, from, to)
	}
	return nil
}
