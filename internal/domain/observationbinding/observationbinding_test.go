package observationbinding

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func valid() Binding {
	at := time.Unix(1700000000, 0).UTC()
	return Binding{
		ID: "b1", TenantID: "t1", EngagementID: "eng1",
		Scope: "semgrep", ExternalIdentity: "fingerprint:abc",
		FindingID: "f1", ObservationID: "o1", Version: 1,
		DecidedBy: "human:alice", Reason: "same injection, confirmed by hand", DecidedAt: at,
	}
}

func TestValidateAcceptsACompleteDecision(t *testing.T) {
	t.Parallel()
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid binding refused: %v", err)
	}
}

func TestADecisionWithoutAnActorOrAReasonIsRefused(t *testing.T) {
	t.Parallel()
	// Without these two a binding is indistinguishable from the automatic merge this type exists to stop.
	cases := map[string]func(*Binding){
		"no actor":     func(b *Binding) { b.DecidedBy = "" },
		"no reason":    func(b *Binding) { b.Reason = "   " },
		"long reason":  func(b *Binding) { b.Reason = strings.Repeat("x", MaxReasonBytes+1) },
		"no finding":   func(b *Binding) { b.FindingID = "" },
		"no lineage":   func(b *Binding) { b.ObservationID = "" },
		"no scope":     func(b *Binding) { b.Scope = "" },
		"no identity":  func(b *Binding) { b.ExternalIdentity = "" },
		"zero version": func(b *Binding) { b.Version = 0 },
		"no time":      func(b *Binding) { b.DecidedAt = time.Time{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b := valid()
			mutate(&b)
			if err := b.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("%s accepted: %v", name, err)
			}
		})
	}
}

func TestSupersededBeforeDecidedIsRefused(t *testing.T) {
	t.Parallel()
	b := valid()
	b.SupersededAt = b.DecidedAt.Add(-time.Second)
	if err := b.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a binding retired before it was made was accepted: %v", err)
	}
}

func TestCurrentIsTrueOnlyWhileNotSuperseded(t *testing.T) {
	t.Parallel()
	b := valid()
	if !b.Current() {
		t.Fatal("a binding with no superseded_at is the one in force")
	}
	b.SupersededAt = b.DecidedAt.Add(time.Hour)
	if b.Current() {
		t.Fatal("a retired binding must not report itself as in force")
	}
}

func TestIdentityNeedsBothHalves(t *testing.T) {
	t.Parallel()
	if err := (Identity{Scope: "semgrep"}).Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a scope with no external identity was accepted: %v", err)
	}
	if err := (Identity{ExternalIdentity: "fingerprint:abc"}).Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an external identity with no scope was accepted: %v", err)
	}
	if err := (Identity{Scope: "semgrep", ExternalIdentity: "fingerprint:abc"}).Validate(); err != nil {
		t.Fatalf("a complete identity was refused: %v", err)
	}
}
