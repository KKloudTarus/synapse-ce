package issue

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rule"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func sampleCandidate() Candidate {
	return Candidate{
		Key: "rule-x:file.go:10", FindingIdentity: "rule-x:file.go:10", RuleKey: "rule-x",
		Type: rule.TypeCodeSmell, Title: "t", Severity: shared.SeverityMedium,
		Language: "Go", File: "file.go", Location: "file.go:10",
	}
}

func TestProjectCreatesOpenIssue(t *testing.T) {
	now := time.Now()
	it, err := Project("tenant", "project", "a1", now, sampleCandidate())
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	if it.Status != StatusOpen || it.Version != 1 || !it.IsNew {
		t.Fatalf("want open/v1/new, got %s/%d/%v", it.Status, it.Version, it.IsNew)
	}
	if it.ID.IsZero() {
		t.Fatal("expected deterministic id")
	}
}

func TestStatusResolvedAndGateExempt(t *testing.T) {
	for _, s := range []Status{StatusAccepted, StatusFalsePositive, StatusWontFix} {
		if !s.Resolved() || !s.GateExempt() {
			t.Errorf("%s should be resolved+gate-exempt", s)
		}
	}
	if StatusOpen.Resolved() || StatusOpen.GateExempt() {
		t.Error("open must not be resolved/gate-exempt")
	}
}

func TestCanTransitionTo(t *testing.T) {
	cases := []struct {
		from, to Status
		ok       bool
	}{
		{StatusOpen, StatusAccepted, true},
		{StatusOpen, StatusFalsePositive, true},
		{StatusOpen, StatusWontFix, true},
		{StatusOpen, StatusOpen, false},
		{StatusAccepted, StatusOpen, true},
		{StatusAccepted, StatusFalsePositive, true},
		{StatusFalsePositive, StatusWontFix, true},
		{StatusWontFix, StatusAccepted, true},
		{StatusAccepted, StatusAccepted, false},
	}
	for _, c := range cases {
		if got := c.from.CanTransitionTo(c.to); got != c.ok {
			t.Errorf("%s->%s: want %v, got %v", c.from, c.to, c.ok, got)
		}
	}
}

func TestTransition(t *testing.T) {
	now := time.Now()
	base, _ := Project("tenant", "project", "a1", now, sampleCandidate())

	t.Run("happy path", func(t *testing.T) {
		updated, event, err := base.Transition(StatusFalsePositive, "alice", "reviewed the data flow", 1, "ev1", now)
		if err != nil {
			t.Fatalf("Transition: %v", err)
		}
		if updated.Status != StatusFalsePositive || updated.Version != 2 || updated.LastReviewedBy != "alice" {
			t.Fatalf("unexpected updated: %+v", updated)
		}
		if event.From != StatusOpen || event.To != StatusFalsePositive || event.Version != 2 {
			t.Fatalf("unexpected event: %+v", event)
		}
	})

	t.Run("stale version conflicts", func(t *testing.T) {
		_, _, err := base.Transition(StatusAccepted, "alice", "looks fine here", 99, "ev2", now)
		if !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("want ErrConflict, got %v", err)
		}
	})

	t.Run("illegal transition", func(t *testing.T) {
		_, _, err := base.Transition(StatusOpen, "alice", "reopen while open", 1, "ev3", now)
		if !errors.Is(err, shared.ErrValidation) || !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("want validation+invalid-transition, got %v", err)
		}
	})

	t.Run("short rationale rejected", func(t *testing.T) {
		_, _, err := base.Transition(StatusAccepted, "alice", "no", 1, "ev4", now)
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want validation, got %v", err)
		}
	})

	t.Run("empty actor rejected", func(t *testing.T) {
		_, _, err := base.Transition(StatusAccepted, "  ", "valid rationale text", 1, "ev5", now)
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want validation, got %v", err)
		}
	})
}
