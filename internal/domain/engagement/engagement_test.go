package engagement

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestNew(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

	t.Run("valid (draft, trimmed)", func(t *testing.T) {
		e, err := New(shared.ID("eng1"), shared.ID(""), "  acme-q3  ", "  Acme  ", now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if e.Name != "acme-q3" || e.Client != "Acme" {
			t.Errorf("name/client not trimmed: %+v", e)
		}
		if e.Status != StatusDraft {
			t.Errorf("status = %q, want draft", e.Status)
		}
	})

	t.Run("blank id rejected", func(t *testing.T) {
		if _, err := New(shared.ID(""), shared.ID(""), "n", "", now); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("want ErrValidation, got %v", err)
		}
	})

	t.Run("blank name rejected", func(t *testing.T) {
		if _, err := New(shared.ID("id"), shared.ID(""), "   ", "", now); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("want ErrValidation, got %v", err)
		}
	})
}

func TestAllowsExecution(t *testing.T) {
	e := &Engagement{}
	for _, st := range []Status{StatusDraft, StatusActive} {
		e.Status = st
		if !e.AllowsExecution() {
			t.Errorf("status %q should allow execution", st)
		}
	}
	for _, st := range []Status{StatusCompleted, StatusArchived} {
		e.Status = st
		if e.AllowsExecution() {
			t.Errorf("status %q should NOT allow execution (test is over)", st)
		}
	}
}

func TestTransition(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		from, to Status
		wantErr  bool
	}{
		{"draft to active", StatusDraft, StatusActive, false},
		{"draft to archived", StatusDraft, StatusArchived, false},
		{"active to completed", StatusActive, StatusCompleted, false},
		{"active to archived", StatusActive, StatusArchived, false},
		{"completed to archived", StatusCompleted, StatusArchived, false},
		{"draft to completed rejected", StatusDraft, StatusCompleted, true},
		{"completed to active rejected", StatusCompleted, StatusActive, true},
		{"archived is terminal", StatusArchived, StatusActive, true},
		{"unknown status rejected", StatusActive, Status("bogus"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := &Engagement{Status: c.from}
			err := e.Transition(c.to, now)
			if c.wantErr {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("want ErrValidation, got %v", err)
				}
				if e.Status != c.from {
					t.Errorf("status mutated on rejected transition: %s", e.Status)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if e.Status != c.to {
				t.Errorf("status = %s, want %s", e.Status, c.to)
			}
			if !e.Audit.UpdatedAt.Equal(now) {
				t.Error("UpdatedAt not stamped on transition")
			}
		})
	}
	t.Run("idempotent same status is a no-op", func(t *testing.T) {
		e := &Engagement{Status: StatusActive}
		if err := e.Transition(StatusActive, now); err != nil {
			t.Fatalf("idempotent transition should not error: %v", err)
		}
	})
}

func TestSetScope(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	e := &Engagement{Status: StatusActive}
	if err := e.SetScope(
		[]Target{{Kind: TargetDomain, Value: "acme.io"}},
		[]Target{{Kind: TargetCIDR, Value: "10.0.0.0/24"}}, now); err != nil {
		t.Fatalf("valid scope rejected: %v", err)
	}
	if len(e.Scope.InScope) != 1 || len(e.Scope.OutOfScope) != 1 || !e.Audit.UpdatedAt.Equal(now) {
		t.Errorf("scope not set / UpdatedAt not stamped: %+v", e.Scope)
	}
	if err := e.SetScope([]Target{{Kind: TargetDomain, Value: "WWW.Example.COM."}, {Kind: TargetURL, Value: "HTTPS://app.example.com/a"}}, nil, now); err != nil {
		t.Fatalf("canonical scope rejected: %v", err)
	}
	if got, want := e.Scope.InScope[0].Value, "www.example.com"; got != want {
		t.Errorf("canonical domain = %q, want %q", got, want)
	}
	if got, want := e.Scope.InScope[1].Value, "https://app.example.com/a"; got != want {
		t.Errorf("canonical URL = %q, want %q", got, want)
	}
	before := e.Scope
	// A malformed target is rejected without partially replacing the existing scope.
	if err := e.SetScope([]Target{{Kind: TargetKind("bogus"), Value: "x"}}, nil, now); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("malformed scope: want ErrValidation, got %v", err)
	}
	if !reflect.DeepEqual(e.Scope, before) {
		t.Errorf("scope changed after rejected update: got %+v, want %+v", e.Scope, before)
	}
}

func TestIsAuthorizedAt(t *testing.T) {
	base := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	from := base.Add(-time.Hour)
	to := base.Add(time.Hour)

	cases := []struct {
		name     string
		from, to *time.Time
		at       time.Time
		want     bool
	}{
		{"no window is open", nil, nil, base, true},
		{"within window", &from, &to, base, true},
		{"before start", &from, &to, from.Add(-5 * time.Minute), false},
		{"after end", &from, &to, to.Add(5 * time.Minute), false},
		{"open start, before end", nil, &to, base, true},
		{"open end, after start", &from, nil, base, true},
		// Clock-skew tolerance (±2m): just past the boundary but within skew is allowed.
		{"within skew after end", &from, &to, to.Add(time.Minute), true},
		{"within skew before start", &from, &to, from.Add(-time.Minute), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := &Engagement{AuthorizedFrom: c.from, AuthorizedTo: c.to}
			if got := e.IsAuthorizedAt(c.at); got != c.want {
				t.Errorf("IsAuthorizedAt = %v, want %v", got, c.want)
			}
		})
	}
}
