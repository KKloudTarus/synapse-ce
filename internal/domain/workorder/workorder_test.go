package workorder

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var (
	testNow      = time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	testNotAfter = testNow.Add(time.Hour)
)

func newValid(t *testing.T) *WorkOrder {
	t.Helper()
	w, err := New("wo1", "t1", "as1", "ag1", "scan.source", "eng1", "idem1", testNotAfter, 42, testNow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return w
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name                                      string
		id, tenant, asset, agent, cap, auth, idem string
		notAfter                                  time.Time
		wantErr                                   bool
	}{
		{"ok", "wo1", "t1", "as1", "ag1", "scan.source", "eng1", "idem1", testNotAfter, false},
		{"missing id", "", "t1", "as1", "ag1", "scan.source", "eng1", "idem1", testNotAfter, true},
		{"empty tenant deny", "wo1", "", "as1", "ag1", "scan.source", "eng1", "idem1", testNotAfter, true},
		{"missing asset", "wo1", "t1", "", "ag1", "scan.source", "eng1", "idem1", testNotAfter, true},
		{"missing agent", "wo1", "t1", "as1", "", "scan.source", "eng1", "idem1", testNotAfter, true},
		{"missing capability", "wo1", "t1", "as1", "ag1", "  ", "eng1", "idem1", testNotAfter, true},
		{"missing authorization", "wo1", "t1", "as1", "ag1", "scan.source", "", "idem1", testNotAfter, true},
		{"missing idempotency", "wo1", "t1", "as1", "ag1", "scan.source", "eng1", " ", testNotAfter, true},
		{"missing not_after", "wo1", "t1", "as1", "ag1", "scan.source", "eng1", "idem1", time.Time{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, err := New(shared.ID(tc.id), shared.ID(tc.tenant), shared.ID(tc.asset), shared.ID(tc.agent),
				tc.cap, shared.ID(tc.auth), tc.idem, tc.notAfter, 1, testNow)
			if tc.wantErr {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("expected ErrValidation, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if w.State != StateIssued {
				t.Fatalf("new order should be issued, got %q", w.State)
			}
		})
	}
}

func TestStateValidAndTerminal(t *testing.T) {
	all := []State{StateIssued, StateClaimed, StateRunning, StateSucceeded, StateFailed, StateExpired, StateCancelled, StateRefused}
	for _, s := range all {
		if !s.Valid() {
			t.Errorf("%q should be valid", s)
		}
	}
	if State("bogus").Valid() {
		t.Errorf("bogus should be invalid")
	}
	terminal := map[State]bool{StateSucceeded: true, StateFailed: true, StateExpired: true, StateCancelled: true, StateRefused: true}
	for _, s := range all {
		if s.Terminal() != terminal[s] {
			t.Errorf("%q terminal mismatch", s)
		}
	}
}

func TestCanTransition(t *testing.T) {
	legal := map[State][]State{
		StateIssued:  {StateClaimed, StateExpired, StateCancelled},
		StateClaimed: {StateRunning, StateRefused, StateExpired, StateCancelled},
		StateRunning: {StateSucceeded, StateFailed, StateCancelled},
	}
	all := []State{StateIssued, StateClaimed, StateRunning, StateSucceeded, StateFailed, StateExpired, StateCancelled, StateRefused}
	for _, from := range all {
		for _, to := range all {
			want := false
			for _, ok := range legal[from] {
				if ok == to {
					want = true
				}
			}
			if got := CanTransition(from, to); got != want {
				t.Errorf("CanTransition(%q,%q)=%v want %v", from, to, got, want)
			}
		}
	}
	// terminal states never transition
	for s := range map[State]bool{StateSucceeded: true, StateFailed: true, StateExpired: true, StateCancelled: true, StateRefused: true} {
		for _, to := range all {
			if CanTransition(s, to) {
				t.Errorf("terminal %q should not transition to %q", s, to)
			}
		}
	}
}

func TestSigningPayloadStableAndCoversFields(t *testing.T) {
	w := newValid(t)
	p1 := w.SigningPayload()
	if p1 != w.SigningPayload() {
		t.Fatalf("signing payload must be deterministic")
	}
	// A tampered capability changes the payload (so it invalidates any signature over it).
	w2 := newValid(t)
	w2.Capability = "scan.host"
	if w2.SigningPayload() == p1 {
		t.Fatalf("changing capability must change the signing payload")
	}
	// A tampered expiry changes the payload.
	w3 := newValid(t)
	w3.NotAfter = testNotAfter.Add(time.Hour)
	if w3.SigningPayload() == p1 {
		t.Fatalf("changing not_after must change the signing payload")
	}
}
