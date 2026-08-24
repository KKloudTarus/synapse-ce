package responsesaga

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

const actionID = shared.ID("act-1")

var base = time.Unix(1_800_000_000, 0).UTC()

func procTarget() TargetFingerprint {
	return TargetFingerprint{Kind: FingerprintProcess, ProcessEntityID: "pe_abc"}
}

func mustSaga(t *testing.T) *Saga {
	t.Helper()
	s, err := NewSaga(actionID, procTarget(), ReversibilityGuaranteed)
	if err != nil {
		t.Fatalf("new saga: %v", err)
	}
	return s
}

func advance(t *testing.T, s *Saga, states ...SagaState) {
	t.Helper()
	for _, st := range states {
		if err := s.Transition(st); err != nil {
			t.Fatalf("transition to %s: %v", st, err)
		}
	}
}

func TestSagaHappyPathToVerifiedContainment(t *testing.T) {
	s := mustSaga(t)
	advance(t, s, StateAwaitingApproval, StateApproved, StateIssued, StateClaimed, StateExecuting, StateCommandApplied, StateVerifying, StateVerifiedSucceeded)
	if !s.Contained() {
		t.Fatal("verified-succeeded must report contained")
	}
	if s.State().Terminal() {
		t.Fatal("verified-succeeded is not itself terminal (it can still finalize or roll back)")
	}
	// Finalizing a verified success reaches a real terminal state while staying contained.
	advance(t, s, StateCompleted)
	if !s.State().Terminal() {
		t.Fatal("completed must be terminal")
	}
	if !s.Contained() {
		t.Fatal("a completed (verified, not reverted) response must still report contained")
	}
	if s.Transition(StateRollbackRequested) == nil {
		t.Fatal("no transition out of a terminal completed state")
	}
}

// TestCommandAppliedIsNotVerifiedSucceeded is the crown invariant: a saga cannot jump from a successful
// command to verified success — it must pass through the telemetry Verifying step.
func TestCommandAppliedIsNotVerifiedSucceeded(t *testing.T) {
	s := mustSaga(t)
	advance(t, s, StateAwaitingApproval, StateApproved, StateIssued, StateClaimed, StateExecuting, StateCommandApplied)
	if err := s.Transition(StateVerifiedSucceeded); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("command_applied -> verified_succeeded must be illegal, got %v", err)
	}
	if s.Contained() {
		t.Fatal("a command applied but not verified must not report contained")
	}
	// The only legal next step is verifying.
	if !CanTransition(StateCommandApplied, StateVerifying) {
		t.Fatal("command_applied must be able to enter verifying")
	}
}

func TestSagaVerificationOutcomesToRollback(t *testing.T) {
	for _, outcome := range []SagaState{StateVerificationFailed, StateVerificationUnknown, StateTimedOut} {
		s := mustSaga(t)
		advance(t, s, StateAwaitingApproval, StateApproved, StateIssued, StateClaimed, StateExecuting, StateCommandApplied, StateVerifying, outcome, StateRollbackRequested, StateRollingBack, StateRolledBack)
		if !s.State().Terminal() {
			t.Fatalf("rolled_back must be terminal (via %s)", outcome)
		}
		if s.Contained() {
			t.Fatalf("a non-succeeded verification (%s) must not report contained", outcome)
		}
	}
}

func TestSagaRejectsIllegalTransitions(t *testing.T) {
	s := mustSaga(t)
	// proposed -> issued (skipping approval) is illegal.
	if err := s.Transition(StateIssued); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("proposed -> issued must be illegal, got %v", err)
	}
	// unknown target state.
	if err := s.Transition("bogus"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown state must be rejected, got %v", err)
	}
	// terminal has no exits.
	advance(t, s, StateRejected)
	if !s.State().Terminal() {
		t.Fatal("rejected must be terminal")
	}
	if s.Transition(StateApproved) == nil {
		t.Fatal("no transition out of a terminal state")
	}
}

func TestTargetFingerprintValidate(t *testing.T) {
	ok := []TargetFingerprint{
		{Kind: FingerprintProcess, ProcessEntityID: "pe_x"},
		{Kind: FingerprintFile, FilePath: "/etc/x", FileDevice: 1, FileInode: 2},
		{Kind: FingerprintFile, FilePath: "/etc/x", FileHash: "abc"},
		{Kind: FingerprintHost, HostID: "host-1", NetpolGeneration: 3},
	}
	for _, f := range ok {
		if err := f.Validate(); err != nil {
			t.Fatalf("valid target rejected: %+v: %v", f, err)
		}
	}
	bad := []TargetFingerprint{
		{Kind: FingerprintProcess},                                 // no stable entity id (bare PID not allowed)
		{Kind: FingerprintFile, FilePath: "/etc/x"},                // path alone is rebindable
		{Kind: FingerprintFile, FilePath: "/etc/x", FileDevice: 1}, // device-only is not a stable identity
		{Kind: FingerprintFile, FilePath: "/etc/x", FileInode: 2},  // inode-only is ambiguous across filesystems
		{Kind: FingerprintFile, FileDevice: 1, FileInode: 2},       // no path
		{Kind: FingerprintHost},                                    // no host id
		{Kind: FingerprintHost, HostID: "host-1"},                  // no netpol generation (staleness undetectable)
		{Kind: "bogus", ProcessEntityID: "pe_x"},
	}
	for _, f := range bad {
		if err := f.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("invalid target accepted: %+v", f)
		}
	}
}

func TestRecordAttemptIdempotentAndValidated(t *testing.T) {
	s := mustSaga(t)
	a := ResponseAttempt{ActionID: actionID, Attempt: 1, IdempotencyKey: "k1", Target: procTarget(), State: StateExecuting, CommandOutcome: "applied", At: base}
	if err := s.RecordAttempt(a); err != nil {
		t.Fatal(err)
	}
	// Same idempotency key -> no-op (at-least-once re-issue).
	if err := s.RecordAttempt(a); err != nil {
		t.Fatal(err)
	}
	if len(s.Attempts()) != 1 {
		t.Fatalf("duplicate idempotency key must not double-journal, got %d", len(s.Attempts()))
	}
	// Same key re-used for a DIFFERENT attempt is rejected (masking it could double-apply a distinct action).
	divergent := a
	divergent.CommandOutcome = "different"
	if err := s.RecordAttempt(divergent); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("re-used idempotency key with a different attempt must be rejected, got %v", err)
	}
	if len(s.Attempts()) != 1 {
		t.Fatalf("a rejected divergent attempt must not be journaled, got %d", len(s.Attempts()))
	}
	// Foreign action rejected.
	if err := s.RecordAttempt(ResponseAttempt{ActionID: "other", Attempt: 1, IdempotencyKey: "k2", Target: procTarget(), State: StateExecuting}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("foreign action attempt must be rejected, got %v", err)
	}
	// Invalid attempt (no key) rejected.
	if err := s.RecordAttempt(ResponseAttempt{ActionID: actionID, Attempt: 1, Target: procTarget(), State: StateExecuting}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("attempt without idempotency key must be rejected, got %v", err)
	}
}

func TestNewSagaValidation(t *testing.T) {
	s := mustSaga(t)
	if s.ActionID() != actionID || s.Target() != procTarget() || s.Reversibility() != ReversibilityGuaranteed || s.State() != StateProposed {
		t.Fatalf("new saga getters wrong: %s %+v %s %s", s.ActionID(), s.Target(), s.Reversibility(), s.State())
	}
	if _, err := NewSaga("", procTarget(), ReversibilityGuaranteed); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("missing action id must be rejected")
	}
	if _, err := NewSaga(actionID, TargetFingerprint{Kind: FingerprintProcess}, ReversibilityGuaranteed); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("invalid target must be rejected")
	}
	if _, err := NewSaga(actionID, procTarget(), "bogus"); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("invalid reversibility must be rejected")
	}
}

func TestOutcomeAndReversibilityValidity(t *testing.T) {
	if !VerificationSucceeded.Valid() || !VerificationUnknown.Valid() || !VerificationPending.Valid() || VerificationOutcome("x").Valid() {
		t.Fatal("verification outcome validity wrong")
	}
	if !ReversibilityGuaranteed.Valid() || !ReversibilityIrreversible.Valid() || ReversibilityClass("x").Valid() {
		t.Fatal("reversibility validity wrong")
	}
}
