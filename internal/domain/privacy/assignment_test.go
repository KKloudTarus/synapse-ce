package privacy

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestAssignmentValidatesImmutablePolicyIdentity(t *testing.T) {
	at := time.Unix(1_750_000_000, 123_456_789).UTC()
	assignment, err := NewAssignment("tenant-1", DefaultPolicy(), "operator", at)
	if err != nil {
		t.Fatalf("NewAssignment() error = %v", err)
	}
	if assignment.CreatedAt.Nanosecond()%1_000 != 0 {
		t.Fatalf("CreatedAt = %s, want microsecond precision", assignment.CreatedAt)
	}
	if err := assignment.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	tampered := assignment
	tampered.Policy = clonePolicy(assignment.Policy)
	tampered.Policy.MaxArgLen--
	if err := tampered.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("tampered Validate() error = %v, want validation", err)
	}
}

func TestSameAssignmentIgnoresLaterServerClockButNotActor(t *testing.T) {
	at := time.Unix(1_750_000_000, 0).UTC()
	first, err := NewAssignment("tenant-1", DefaultPolicy(), "operator", at)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := NewAssignment("tenant-1", DefaultPolicy(), "operator", at.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !SameAssignment(first, retry) {
		t.Fatal("same declarative policy under a later server clock must be idempotent")
	}
	retry.CreatedBy = "other-operator"
	if SameAssignment(first, retry) {
		t.Fatal("different immutable actor must conflict")
	}
}

func TestNewAssignmentRejectsRelaxedSourcePolicy(t *testing.T) {
	policy := DefaultPolicy()
	policy.Dispositions[CategoryProcessEnv] = DispositionAllow
	if _, err := NewAssignment("tenant-1", policy, "operator", time.Now()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("NewAssignment() error = %v, want validation", err)
	}
}
