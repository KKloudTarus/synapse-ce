package incident

import "testing"

func TestStateValidAndTransitions(t *testing.T) {
	if !StateOpen.Valid() || State("bogus").Valid() {
		t.Fatal("Valid() wrong")
	}
	legal := [][2]State{
		{StateNew, StateOpen}, {StateNew, StateInvestigating}, {StateOpen, StateInvestigating}, {StateInvestigating, StateContained},
		{StateContained, StateRemediated}, {StateRemediated, StateResolved}, {StateResolved, StateClosed},
		{StateClosed, StateReopened}, {StateReopened, StateInvestigating}, {StateResolved, StateReopened},
	}
	for _, tc := range legal {
		if !CanTransition(tc[0], tc[1]) {
			t.Fatalf("expected legal transition %s -> %s", tc[0], tc[1])
		}
	}
	illegal := [][2]State{
		{StateOpen, StateResolved},  // must pass through investigation/containment
		{StateNew, StateResolved},   // can't jump to resolved
		{StateClosed, StateOpen},    // closed only reopens
		{StateResolved, StateOpen},  // resolved only closes or reopens
		{StateOpen, State("bogus")}, // unknown target
	}
	for _, tc := range illegal {
		if CanTransition(tc[0], tc[1]) {
			t.Fatalf("expected illegal transition %s -> %s", tc[0], tc[1])
		}
	}
}
