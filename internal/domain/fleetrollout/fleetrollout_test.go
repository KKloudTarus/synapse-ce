package fleetrollout

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func plan(target string, canary []string, promoted bool) *Plan {
	return &Plan{
		TenantID: "t1", Channel: DefaultChannel,
		TargetVersion: target, CanaryGroups: canary, PromotedToAll: promoted,
	}
}

// TestNoOfferWithoutAnExplicitOperatorDecision is the central prohibition: there is no unconditional
// fleet-wide auto-update, so every path that lacks a deliberate operator choice declines.
func TestNoOfferWithoutAnExplicitOperatorDecision(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		plan    *Plan
		group   string
		version string
		reason  Reason
	}{
		{"no plan at all", nil, "default", "1.0.0", ReasonNoPlan},
		{"plan with no target", plan("", nil, false), "default", "1.0.0", ReasonNoTarget},
		{"target not yet promoted, agent outside the canary", plan("2.0.0", []string{"canary"}, false), "default", "1.0.0", ReasonCanaryOnly},
		{"paused", &Plan{TenantID: "t1", Channel: "stable", TargetVersion: "2.0.0", CanaryGroups: []string{"default"}, PromotedToAll: true, Paused: true, PauseReason: "regression"}, "default", "1.0.0", ReasonPaused},
		{"agent version cannot be compared", plan("2.0.0", []string{"default"}, true), "default", "not-a-version", ReasonUnparseableAgent},
		{"agent already at the target", plan("2.0.0", []string{"default"}, true), "default", "2.0.0", ReasonUpToDate},
		{"agent ahead of the target — never a downgrade", plan("1.0.0", []string{"default"}, true), "default", "2.0.0", ReasonUpToDate},
		{"stored target is unparseable", plan("garbage", []string{"default"}, true), "default", "1.0.0", ReasonNoTarget},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := Decide(test.plan, test.group, test.version)
			if got.Offer {
				t.Fatalf("%s must NOT offer an update, got target %q", test.name, got.Target)
			}
			if got.Target != "" {
				t.Fatalf("a declined decision must carry no target, got %q", got.Target)
			}
			if got.Reason != test.reason {
				t.Fatalf("reason = %q, want %q", got.Reason, test.reason)
			}
		})
	}
}

// The two paths that DO offer are the two an operator explicitly authorised.
func TestOfferRequiresCanaryMembershipOrPromotion(t *testing.T) {
	t.Parallel()

	canaryPlan := plan("2.0.0", []string{"canary", "lab"}, false)
	got := Decide(canaryPlan, "canary", "1.0.0")
	if !got.Offer || got.Target != "2.0.0" || got.Reason != ReasonCanary {
		t.Fatalf("a canary group must be offered the target, got %+v", got)
	}
	// A different group is still held back by the same plan.
	if held := Decide(canaryPlan, "prod", "1.0.0"); held.Offer {
		t.Fatalf("a non-canary group must wait for promotion, got %+v", held)
	}

	promoted := plan("2.0.0", []string{"canary"}, true)
	if got := Decide(promoted, "prod", "1.0.0"); !got.Offer || got.Reason != ReasonPromoted {
		t.Fatalf("after promotion every group is offered the target, got %+v", got)
	}
}

// An agent with no assigned group falls into DefaultGroup, and a plan can target that group like any
// other. It must not be a hole that receives everything or nothing by accident.
func TestUnassignedAgentUsesTheDefaultGroup(t *testing.T) {
	t.Parallel()

	if got := Decide(plan("2.0.0", []string{DefaultGroup}, false), "", "1.0.0"); !got.Offer {
		t.Fatalf("an unassigned agent is in %q and must be offered when that group is a canary, got %+v", DefaultGroup, got)
	}
	if got := Decide(plan("2.0.0", []string{"canary"}, false), "  ", "1.0.0"); got.Offer {
		t.Fatalf("an unassigned agent must not be offered a canary-only target, got %+v", got)
	}
}

// TestPromotionRequiresACanaryFirst locks the shape of the control: "promote" must mean "the canary
// held", never "skip straight to every host".
func TestPromotionRequiresACanaryFirst(t *testing.T) {
	t.Parallel()

	err := Plan{TenantID: "t1", Channel: "stable", TargetVersion: "2.0.0", PromotedToAll: true}.Validate()
	if err == nil {
		t.Fatal("promoting without a canary group is the unconditional fleet-wide update this design forbids")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("error %v must wrap ErrValidation", err)
	}

	if err := (Plan{TenantID: "t1", Channel: "stable", PromotedToAll: true, CanaryGroups: []string{"c"}}).Validate(); err == nil {
		t.Fatal("promoting without a target version is meaningless and must be refused")
	}
}

func TestPlanValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		plan Plan
		ok   bool
	}{
		{"resting plan with no target", Plan{TenantID: "t1", Channel: "stable"}, true},
		{"canary in progress", Plan{TenantID: "t1", Channel: "stable", TargetVersion: "1.2.3", CanaryGroups: []string{"canary"}}, true},
		{"promoted", Plan{TenantID: "t1", Channel: "stable", TargetVersion: "1.2.3", CanaryGroups: []string{"canary"}, PromotedToAll: true}, true},
		{"paused with a reason", Plan{TenantID: "t1", Channel: "stable", TargetVersion: "1.2.3", Paused: true, PauseReason: "regression in canary"}, true},
		{"no tenant", Plan{Channel: "stable"}, false},
		{"no channel", Plan{TenantID: "t1"}, false},
		{"unparseable target", Plan{TenantID: "t1", Channel: "stable", TargetVersion: "next"}, false},
		{"paused with no reason", Plan{TenantID: "t1", Channel: "stable", Paused: true}, false},
		{"bad group name", Plan{TenantID: "t1", Channel: "stable", CanaryGroups: []string{"has space"}}, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := test.plan.Validate()
			if test.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !test.ok && err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

func TestGroupValidation(t *testing.T) {
	t.Parallel()

	for _, ok := range []string{"default", "canary", "eu-west-1", "prod_2", "a.b"} {
		if err := ValidateGroup(ok); err != nil {
			t.Fatalf("group %q must be accepted: %v", ok, err)
		}
	}
	for _, bad := range []string{"", " ", "has space", "trailing ", "sla/sh", "quote\"", string(rune(0x202e)) + "evil"} {
		if err := ValidateGroup(bad); err == nil {
			t.Fatalf("group %q must be refused", bad)
		}
	}
}

// Canary lists are normalized so a decision cannot depend on the order or casing an operator typed,
// and so a stored plan is byte-identical for the same intent.
func TestCanaryGroupsAreNormalized(t *testing.T) {
	t.Parallel()

	got, err := NormalizeCanaryGroups([]string{" prod ", "canary", "canary", "", "  ", "alpha"})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	want := []string{"alpha", "canary", "prod"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if _, err := NormalizeCanaryGroups([]string{"has space"}); err == nil {
		t.Fatal("an invalid group must fail normalization rather than being silently dropped")
	}
}

// A declined decision must always explain itself; an unexplained silence is indistinguishable from a
// stuck rollout.
func TestEveryDecisionCarriesAReason(t *testing.T) {
	t.Parallel()

	for _, d := range []Decision{
		Decide(nil, "default", "1.0.0"),
		Decide(plan("2.0.0", []string{"canary"}, false), "prod", "1.0.0"),
		Decide(plan("2.0.0", []string{"prod"}, false), "prod", "1.0.0"),
	} {
		if d.Reason == "" {
			t.Fatalf("decision %+v carries no reason", d)
		}
	}
}
