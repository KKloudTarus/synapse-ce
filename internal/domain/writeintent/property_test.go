package writeintent

import (
	"errors"
	"math/rand"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Random legal and illegal walks must preserve the safety invariant: an
// ambiguous write never becomes pending without an explicit reconciliation.
func TestStateMachineProperties(t *testing.T) {
	events := []Event{Claim, Acknowledge, Reject, Ambiguous, LeaseExpired,
		RetryFailed, ReconcileAbsent, ReconcileFound, ReconcileMultiple, Event("unexpected")}
	for seed := int64(0); seed < 256; seed++ {
		r := rand.New(rand.NewSource(seed))
		state := Pending
		for step := 0; step < 128; step++ {
			event := events[r.Intn(len(events))]
			next, err := Next(state, event)
			if err != nil {
				if !errors.Is(err, shared.ErrConflict) || next != "" {
					t.Fatalf("seed=%d step=%d rejected transition %s + %s returned %s, %v",
						seed, step, state, event, next, err)
				}
				continue
			}
			if !next.Valid() {
				t.Fatalf("seed=%d step=%d generated invalid state %s", seed, step, next)
			}
			if state == Uncertain && event != ReconcileAbsent && event != ReconcileFound && event != ReconcileMultiple {
				t.Fatalf("seed=%d step=%d uncertain left without reconciliation", seed, step)
			}
			if next == Pending && !((state == Failed && event == RetryFailed) || (state == Uncertain && event == ReconcileAbsent)) {
				t.Fatalf("seed=%d step=%d reached pending from %s + %s", seed, step, state, event)
			}
			if state == Done {
				t.Fatalf("seed=%d step=%d terminal intent mutated", seed, step)
			}
			if next == InFlight && (state != Pending || event != Claim) {
				t.Fatalf("seed=%d step=%d created unclaimed in-flight intent", seed, step)
			}
			state = next
		}
	}
}
func FuzzNext(f *testing.F) {
	for _, seed := range [][]byte{[]byte("pending:claim"), []byte("in_flight:ambiguous"),
		[]byte("uncertain:claim"), []byte("uncertain:reconcile_absent"),
		[]byte("done:claim"), []byte("invalid:invalid")} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 256 {
			return
		}
		states := []State{Pending, InFlight, Done, Failed, Uncertain, State(string(data))}
		events := []Event{Claim, Acknowledge, Reject, Ambiguous, LeaseExpired, RetryFailed,
			ReconcileAbsent, ReconcileFound, ReconcileMultiple, Event(string(data))}
		var hash uint
		for _, v := range data {
			hash = hash*33 + uint(v)
		}
		s := states[int(hash%uint(len(states)))]
		e := events[int((hash/2)%uint(len(events)))]
		next, err := Next(s, e)
		if err == nil && !next.Valid() {
			t.Fatal("invalid successful state")
		}
		if s == Uncertain && e == Claim && !errors.Is(err, shared.ErrConflict) {
			t.Fatal("uncertain intent was claimed without reconciliation")
		}
		if err == nil && next == Pending && !((s == Failed && e == RetryFailed) || (s == Uncertain && e == ReconcileAbsent)) {
			t.Fatalf("reached pending from %s + %s", s, e)
		}
		if s == Done && err == nil {
			t.Fatal("terminal intent mutated")
		}
	})
}
