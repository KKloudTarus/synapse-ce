// Package baseline is the pure-domain behavioral-baseline model for Phase D of the EDR data plane
// (#594, D1-D4). It learns normal per-entity/peer-group behavior and scores how far a fresh observation
// deviates — an anomaly that becomes a RiskContext.Behavior FACTOR, never a verdict. Its disciplines
// mirror the rest of the data plane: deterministic + reorder-invariant folds (so a baseline summary is
// reproducible for evidence), fail-closed validation, and coverage-honesty — a baseline yields an anomaly
// score ONLY while it is trustworthy (state == active); otherwise it abstains, which lowers Coverage,
// never Risk. The eBPF collection and the live scoring loop are composed on top (deferred agent tail).
package baseline

import (
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// State is where a baseline sits in its trust lifecycle. A baseline is trustworthy for anomaly
// scoring ONLY in StateActive; every other state means "do not score from me" (coverage-honesty).
type State string

const (
	// StateLearning: accumulating observations, not yet enough to score (cold-start).
	StateLearning State = "learning"
	// StateActive: enough clean observations; the ONLY state that yields an anomaly score.
	StateActive State = "active"
	// StateStale: no recent observations; not scoreable until fresh data revives it.
	StateStale State = "stale"
	// StateDrifted: sustained divergence detected; must re-baseline before scoring again.
	StateDrifted State = "drifted"
	// StatePoisoned: learned from (or suspected of) tainted data; must re-baseline.
	StatePoisoned State = "poisoned"
	// StateResetPending: marked for a clean re-baseline; transitions back to learning.
	StateResetPending State = "reset_pending"
	// StateDisabled: operator-disabled; terminal (re-enabling means a fresh baseline).
	StateDisabled State = "disabled"
)

// transitions is the legal lifecycle graph. Learning gathers until active; active keeps learning online
// but can go stale/drifted/poisoned; drift and poison both force a reset_pending -> learning re-baseline.
// disabled is terminal. Crucially StateActive is the sole Scoreable() state.
var transitions = map[State][]State{
	StateLearning:     {StateActive, StatePoisoned, StateDisabled},
	StateActive:       {StateStale, StateDrifted, StatePoisoned, StateDisabled},
	StateStale:        {StateActive, StateDrifted, StatePoisoned, StateDisabled},
	StateDrifted:      {StateResetPending, StateDisabled},
	StatePoisoned:     {StateResetPending, StateDisabled},
	StateResetPending: {StateLearning, StateDisabled},
	StateDisabled:     {},
}

// Valid reports whether s is a known state.
func (s State) Valid() bool {
	_, ok := transitions[s]
	return ok
}

// Terminal reports whether s has no outgoing transitions (only StateDisabled).
func (s State) Terminal() bool {
	next, ok := transitions[s]
	return ok && len(next) == 0
}

// Scoreable reports whether a baseline in this state may yield an anomaly score. Only StateActive is
// trustworthy; any other state abstains (which lowers Coverage, never Risk).
func (s State) Scoreable() bool { return s == StateActive }

// CanTransition reports whether from -> to is a legal baseline transition.
func CanTransition(from, to State) bool {
	for _, n := range transitions[from] {
		if n == to {
			return true
		}
	}
	return false
}

func requireTransition(from, to State) error {
	if !to.Valid() {
		return fmt.Errorf("%w: unknown baseline state %q", shared.ErrValidation, to)
	}
	if !CanTransition(from, to) {
		return fmt.Errorf("%w: illegal baseline transition %s -> %s", shared.ErrValidation, from, to)
	}
	return nil
}
