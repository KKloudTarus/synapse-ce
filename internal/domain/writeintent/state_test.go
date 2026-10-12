package writeintent

import (
	"errors"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"testing"
)

func TestAllTransitionsAndNoBlindRetry(t *testing.T) {
	accepted := map[State]map[Event]State{
		Pending:   {Claim: InFlight},
		InFlight:  {Acknowledge: Done, Reject: Failed, Ambiguous: Uncertain, LeaseExpired: Uncertain},
		Failed:    {RetryFailed: Pending},
		Uncertain: {ReconcileAbsent: Pending, ReconcileFound: Done, ReconcileMultiple: Uncertain},
		Done:      {},
	}
	events := []Event{Claim, Acknowledge, Reject, Ambiguous, LeaseExpired, RetryFailed, ReconcileAbsent, ReconcileFound, ReconcileMultiple, Event("unknown")}
	for _, state := range []State{Pending, InFlight, Failed, Uncertain, Done, State("unknown")} {
		for _, event := range events {
			got, err := Next(state, event)
			want, allowed := accepted[state][event]
			if allowed && (err != nil || got != want) {
				t.Errorf("%s + %s: got %s, %v; want %s", state, event, got, err, want)
			}
			if !allowed && (!errors.Is(err, shared.ErrConflict) || got != "") {
				t.Errorf("%s + %s: forbidden transition got %s, %v", state, event, got, err)
			}
		}
	}
	for _, state := range []State{Pending, InFlight, Done, Failed, Uncertain} {
		if !state.Valid() {
			t.Errorf("%q should be valid", state)
		}
	}
	if State("bad").Valid() || Pending.Terminal() || !Done.Terminal() {
		t.Fatal("invalid state classification")
	}
}
