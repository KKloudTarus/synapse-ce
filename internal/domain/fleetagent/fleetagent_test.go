package fleetagent

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var tNow = time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)

func TestNewAgent(t *testing.T) {
	tests := []struct {
		name              string
		id, tenant, aName string
		hash              string
		wantErr           bool
	}{
		{"ok", "a1", "t1", "agent-1", "hash", false},
		{"missing id", "", "t1", "agent-1", "hash", true},
		{"empty tenant", "a1", "", "agent-1", "hash", true},
		{"missing name", "a1", "t1", "  ", "hash", true},
		{"missing hash", "a1", "t1", "agent-1", " ", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, err := NewAgent(shared.ID(tc.id), shared.ID(tc.tenant), tc.aName, "linux", "5.15", "0.1.0", []string{"scan.host", "scan.host", ""}, tc.hash, tNow)
			if tc.wantErr {
				if !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("expected ErrValidation, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if a.State != StateActive || a.Revoked() {
				t.Fatalf("new agent should be active")
			}
			if len(a.Capabilities) != 1 || a.Capabilities[0] != "scan.host" {
				t.Fatalf("capabilities should dedupe and drop empties, got %v", a.Capabilities)
			}
		})
	}
}

func TestEnrolToken(t *testing.T) {
	if _, err := NewEnrolToken("", "t1", "op", tNow.Add(time.Hour), tNow); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty hash should fail")
	}
	if _, err := NewEnrolToken("h", "", "op", tNow.Add(time.Hour), tNow); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty tenant should fail")
	}
	if _, err := NewEnrolToken("h", "t1", "op", tNow, tNow); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("non-future expiry should fail")
	}
	tok, err := NewEnrolToken("h", "t1", "op", tNow.Add(time.Hour), tNow)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !tok.Usable(tNow) {
		t.Fatalf("fresh token should be usable")
	}
	if tok.Usable(tNow.Add(2 * time.Hour)) {
		t.Fatalf("expired token should not be usable")
	}
	tok.UsedAt = tNow
	if tok.Usable(tNow) {
		t.Fatalf("used token should not be usable")
	}
}

func TestDecommission(t *testing.T) {
	mk := func() *Agent {
		a, err := NewAgent("a1", "t1", "agent", "linux", "5.15", "0.1.0", nil, "hash", tNow)
		if err != nil {
			t.Fatalf("new agent: %v", err)
		}
		return a
	}

	// A clean decommission moves an active agent to the terminal decommissioned state, self-reported
	// (no operator attribution), and marks it removed.
	a := mk()
	later := tNow.Add(time.Hour)
	a.Decommission(later)
	if a.State != StateDecommissioned || !a.Decommissioned() || !a.Removed() {
		t.Fatalf("decommission did not set terminal state: %+v", a)
	}
	if a.DecommissionedAt == nil || !a.DecommissionedAt.Equal(later) || a.RevokedBy != "" {
		t.Fatalf("decommission attribution wrong: at=%v by=%q", a.DecommissionedAt, a.RevokedBy)
	}
	if a.Revoked() {
		t.Fatalf("a decommissioned agent is not revoked")
	}

	// Re-decommissioning an already-decommissioned agent is idempotent: it refreshes the timestamp and
	// stays decommissioned (never toggles back).
	evenLater := later.Add(time.Hour)
	a.Decommission(evenLater)
	if a.State != StateDecommissioned || a.DecommissionedAt == nil || !a.DecommissionedAt.Equal(evenLater) {
		t.Fatalf("re-decommission should refresh the timestamp and stay decommissioned: %+v", a)
	}

	// Decommission must NOT overwrite an operator revocation (the stronger terminal state).
	r := mk()
	r.Revoke("op", "compromised", tNow)
	r.Decommission(later)
	if r.State != StateRevoked || r.Decommissioned() {
		t.Fatalf("decommission overwrote a revocation: %s", r.State)
	}
	if !r.Removed() {
		t.Fatalf("a revoked agent is removed")
	}
	if !StateDecommissioned.Valid() {
		t.Fatalf("decommissioned must be a valid state")
	}
}
