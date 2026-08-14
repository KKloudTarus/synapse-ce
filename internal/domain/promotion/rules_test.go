package promotion

import (
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func baseSnapshot() Snapshot {
	return Snapshot{
		FindingID:      "finding-1",
		FindingVersion: 1,
		Priority:       3,
		Reachability:   judgment.ReachUnknown,
		ReachabilitySignal: Signal{
			Kind: judgment.PromotionInputReachability,
			ID:   "reach-j1",
		},
	}
}

func TestEvaluateDeterministicEscalation(t *testing.T) {
	cases := []struct {
		name     string
		priority int
		want     int
	}{
		{"P5 to P4", 5, 4},
		{"P4 to P3", 4, 3},
		{"P3 to P2", 3, 2},
		{"P2 to P1", 2, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := baseSnapshot()
			s.Priority = tc.priority
			s.Reachability = judgment.Reachable
			s.ReachabilityPublishable = true
			s.PathPresent = true
			s.PathConfident = true
			s.AttackPathSignal = Signal{Kind: judgment.PromotionInputAttackPath, ID: "ap-1"}
			s.DetectionSignals = []Signal{{Kind: judgment.PromotionInputDetection, ID: "det-1"}}
			got, err := Evaluate(s)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if got == nil {
				t.Fatal("expected a claim, got nil")
			}
			if got.Rule != judgment.RuleRuntimeReachableExposed {
				t.Errorf("rule = %s, want %s", got.Rule, judgment.RuleRuntimeReachableExposed)
			}
			if got.Proposed != judgment.PromotionEscalate {
				t.Errorf("proposed = %s, want escalate", got.Proposed)
			}
			if got.BeforePriority != tc.priority {
				t.Errorf("before = %d, want %d", got.BeforePriority, tc.priority)
			}
			if got.AfterPriority != tc.want {
				t.Errorf("after = %d, want %d", got.AfterPriority, tc.want)
			}
		})
	}
}

func TestEvaluateDeterministicEscalationBoundary(t *testing.T) {
	s := baseSnapshot()
	s.Priority = 1
	s.Reachability = judgment.Reachable
	s.ReachabilityPublishable = true
	s.PathPresent = true
	s.PathConfident = true
	s.AttackPathSignal = Signal{Kind: judgment.PromotionInputAttackPath, ID: "ap-1"}
	s.DetectionSignals = []Signal{{Kind: judgment.PromotionInputDetection, ID: "det-1"}}
	got, err := Evaluate(s)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got != nil {
		t.Errorf("P1 must not escalate; got after=%d", got.AfterPriority)
	}
}

func TestEvaluateDeterministicUnreachability(t *testing.T) {
	cases := []struct {
		name     string
		priority int
		want     int
	}{
		{"P1 to P2", 1, 2},
		{"P3 to P4", 3, 4},
		{"P4 to P5", 4, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := baseSnapshot()
			s.Priority = tc.priority
			s.Reachability = judgment.NotReachable
			s.ReachabilityPublishable = true
			s.ReachabilityDeterministic = true
			got, err := Evaluate(s)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if got == nil {
				t.Fatal("expected a claim, got nil")
			}
			if got.Rule != judgment.RuleDeterministicUnreachable {
				t.Errorf("rule = %s, want %s", got.Rule, judgment.RuleDeterministicUnreachable)
			}
			if got.Proposed != judgment.PromotionDeescalate {
				t.Errorf("proposed = %s, want de_escalate", got.Proposed)
			}
			if got.AfterPriority != tc.want {
				t.Errorf("after = %d, want %d", got.AfterPriority, tc.want)
			}
		})
	}
}

func TestEvaluateSkipsRepeatedDeterministicDeescalationForMatchingSignal(t *testing.T) {
	s := baseSnapshot()
	s.Priority = 4
	s.Reachability = judgment.NotReachable
	s.ReachabilityPublishable = true
	s.ReachabilityDeterministic = true
	s.PriorEscalation = &PriorEscalation{DeescalationInputsMatch: true}
	got, err := Evaluate(s)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("matching deterministic signal must not cascade P4 to P5: %+v", got)
	}
}

func TestEvaluateChangedDeterministicDeescalationSignalProposesAgain(t *testing.T) {
	s := baseSnapshot()
	s.Priority = 4
	s.Reachability = judgment.NotReachable
	s.ReachabilityPublishable = true
	s.ReachabilityDeterministic = true
	s.PriorEscalation = &PriorEscalation{DeescalationInputsMatch: false}
	got, err := Evaluate(s)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.AfterPriority != 5 {
		t.Fatalf("changed deterministic signal must propose P4 to P5: %+v", got)
	}
}

func TestEvaluateDeterministicUnreachabilityBoundary(t *testing.T) {
	s := baseSnapshot()
	s.Priority = 5
	s.Reachability = judgment.NotReachable
	s.ReachabilityPublishable = true
	s.ReachabilityDeterministic = true
	got, err := Evaluate(s)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got != nil {
		t.Errorf("P5 must not de-escalate; got after=%d", got.AfterPriority)
	}
}

func TestEvaluateExactReversal(t *testing.T) {
	s := baseSnapshot()
	s.Priority = 2
	s.PriorEscalation = &PriorEscalation{
		EventID:        "evt-1",
		BeforePriority: 4,
		InputsActive:   false,
	}
	got, err := Evaluate(s)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got == nil {
		t.Fatal("expected a reversal claim, got nil")
	}
	if got.Rule != judgment.RuleCorroboratingSignalLoss {
		t.Errorf("rule = %s, want %s", got.Rule, judgment.RuleCorroboratingSignalLoss)
	}
	if got.Proposed != judgment.PromotionDeescalate {
		t.Errorf("proposed = %s, want de_escalate", got.Proposed)
	}
	if got.AfterPriority != 4 {
		t.Errorf("after = %d, want 4 (exact prior priority)", got.AfterPriority)
	}
}

func TestEvaluateExactReversalSkipsWhenPriorNotHigher(t *testing.T) {
	s := baseSnapshot()
	s.Priority = 3
	s.PriorEscalation = &PriorEscalation{
		EventID:        "evt-1",
		BeforePriority: 3,
		InputsActive:   false,
	}
	got, err := Evaluate(s)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got != nil && got.Rule == judgment.RuleCorroboratingSignalLoss {
		t.Errorf("reversal should not fire when prior=%d <= current=%d", 3, s.Priority)
	}
}

func TestEvaluateReversalSkipsWhenInputsStillActive(t *testing.T) {
	s := baseSnapshot()
	s.Priority = 2
	s.PriorEscalation = &PriorEscalation{
		EventID:        "evt-1",
		BeforePriority: 4,
		InputsActive:   true,
	}
	got, err := Evaluate(s)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got != nil && got.Rule == judgment.RuleCorroboratingSignalLoss {
		t.Error("reversal must not fire when inputs are still active")
	}
}

func TestEvaluateSkipsRepeatedEscalationForMatchingAppliedInputs(t *testing.T) {
	s := baseSnapshot()
	s.Priority = 2
	s.Reachability = judgment.Reachable
	s.ReachabilityPublishable = true
	s.PathPresent = true
	s.PathConfident = true
	s.AttackPathSignal = Signal{Kind: judgment.PromotionInputAttackPath, ID: "ap-1"}
	s.DetectionSignals = []Signal{{Kind: judgment.PromotionInputDetection, ID: "det-1", EvidenceID: "ev-1"}}
	s.PriorEscalation = &PriorEscalation{EventID: "evt-1", BeforePriority: 3, InputsActive: true, InputsMatch: true}
	got, err := Evaluate(s)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got != nil {
		t.Fatalf("matching applied inputs must not cascade priority, got %+v", got)
	}
}

func TestEvaluateEscalatesForChangedInputsAfterApplication(t *testing.T) {
	s := baseSnapshot()
	s.Priority = 2
	s.Reachability = judgment.Reachable
	s.ReachabilityPublishable = true
	s.PathPresent = true
	s.PathConfident = true
	s.AttackPathSignal = Signal{Kind: judgment.PromotionInputAttackPath, ID: "ap-1"}
	s.DetectionSignals = []Signal{{Kind: judgment.PromotionInputDetection, ID: "det-2", EvidenceID: "ev-2"}}
	s.PriorEscalation = &PriorEscalation{EventID: "evt-1", BeforePriority: 3, InputsActive: true, InputsMatch: false}
	got, err := Evaluate(s)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got == nil || got.Proposed != judgment.PromotionEscalate || got.AfterPriority != 1 {
		t.Fatalf("changed inputs must allow a distinct escalation, got %+v", got)
	}
}

func TestEvaluateUncertainCorroboration(t *testing.T) {
	cases := []struct {
		name        string
		confident   bool
		publishable bool
		reach       judgment.ReachabilityState
		wantTokens  []string
	}{
		{
			name:        "inferred path + unknown reachability",
			confident:   false,
			publishable: false,
			reach:       judgment.ReachUnknown,
			wantTokens:  []string{"inferred_edge", "unknown_reachability"},
		},
		{
			name:        "inferred path only",
			confident:   false,
			publishable: true,
			reach:       judgment.Reachable,
			wantTokens:  []string{"inferred_edge"},
		},
		{
			name:        "unknown reachability only",
			confident:   true,
			publishable: false,
			reach:       judgment.ReachUnknown,
			wantTokens:  []string{"unknown_reachability"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := baseSnapshot()
			s.Reachability = tc.reach
			s.ReachabilityPublishable = tc.publishable
			s.PathPresent = true
			s.PathConfident = tc.confident
			s.AttackPathSignal = Signal{Kind: judgment.PromotionInputAttackPath, ID: "ap-1"}
			s.DetectionSignals = []Signal{{Kind: judgment.PromotionInputDetection, ID: "det-1"}}
			got, err := Evaluate(s)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if got == nil {
				t.Fatal("expected a review claim, got nil")
			}
			if got.Rule != judgment.RuleUncertainCorroboration {
				t.Errorf("rule = %s, want %s", got.Rule, judgment.RuleUncertainCorroboration)
			}
			if got.Proposed != judgment.PromotionFlagForReview {
				t.Errorf("proposed = %s, want flag_for_review", got.Proposed)
			}
			if got.AfterPriority != s.Priority {
				t.Errorf("review must not change priority: after=%d, want=%d", got.AfterPriority, s.Priority)
			}
			if len(got.Uncertainty) != len(tc.wantTokens) {
				t.Fatalf("uncertainty tokens = %v, want %v", got.Uncertainty, tc.wantTokens)
			}
			for i, tok := range got.Uncertainty {
				if tok != tc.wantTokens[i] {
					t.Errorf("uncertainty[%d] = %s, want %s", i, tok, tc.wantTokens[i])
				}
			}
		})
	}
}

func TestEvaluateNoDetectionReturnsNil(t *testing.T) {
	s := baseSnapshot()
	s.PathPresent = true
	s.PathConfident = true
	s.DetectionSignals = nil
	got, err := Evaluate(s)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got != nil {
		t.Error("no detections must return nil")
	}
}

func TestEvaluateNoPathReturnsNil(t *testing.T) {
	s := baseSnapshot()
	s.PathPresent = false
	s.DetectionSignals = []Signal{{Kind: judgment.PromotionInputDetection, ID: "det-1"}}
	got, err := Evaluate(s)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got != nil {
		t.Error("no path must return nil")
	}
}

func TestEvaluateDeterminismIdempotentFingerprint(t *testing.T) {
	s := baseSnapshot()
	s.Reachability = judgment.Reachable
	s.ReachabilityPublishable = true
	s.PathPresent = true
	s.PathConfident = true
	s.AttackPathSignal = Signal{Kind: judgment.PromotionInputAttackPath, ID: "ap-1"}
	s.DetectionSignals = []Signal{
		{Kind: judgment.PromotionInputDetection, ID: "det-b"},
		{Kind: judgment.PromotionInputDetection, ID: "det-a"},
	}
	first, err := Evaluate(s)
	if err != nil {
		t.Fatalf("first Evaluate: %v", err)
	}
	second, err := Evaluate(s)
	if err != nil {
		t.Fatalf("second Evaluate: %v", err)
	}
	if first.Fingerprint != second.Fingerprint {
		t.Errorf("fingerprint not deterministic: %s != %s", first.Fingerprint, second.Fingerprint)
	}
}

func TestEvaluateInputSorting(t *testing.T) {
	s := baseSnapshot()
	s.Reachability = judgment.Reachable
	s.ReachabilityPublishable = true
	s.PathPresent = true
	s.PathConfident = true
	s.AttackPathSignal = Signal{Kind: judgment.PromotionInputAttackPath, ID: "ap-z"}
	s.DetectionSignals = []Signal{
		{Kind: judgment.PromotionInputDetection, ID: "det-m"},
		{Kind: judgment.PromotionInputDetection, ID: "det-a"},
	}
	got, err := Evaluate(s)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	for i := 1; i < len(got.Inputs); i++ {
		prev, cur := got.Inputs[i-1], got.Inputs[i]
		if prev.Kind > cur.Kind || (prev.Kind == cur.Kind && prev.ID >= cur.ID) {
			t.Errorf("inputs not sorted at %d: %+v >= %+v", i-1, prev, cur)
		}
	}
}

func TestEvaluateInvalidSnapshot(t *testing.T) {
	cases := []struct {
		name string
		snap Snapshot
	}{
		{"zero finding id", Snapshot{FindingID: "", FindingVersion: 1, Priority: 3}},
		{"zero version", Snapshot{FindingID: "f1", FindingVersion: 0, Priority: 3}},
		{"priority zero", Snapshot{FindingID: "f1", FindingVersion: 1, Priority: 0}},
		{"priority too high", Snapshot{FindingID: "f1", FindingVersion: 1, Priority: 6}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Evaluate(tc.snap)
			if !errors.Is(err, shared.ErrValidation) {
				t.Errorf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestRulesCatalogueDriftGuard(t *testing.T) {
	rules := Rules()
	if len(rules) == 0 {
		t.Fatal("Rules() returned empty; the drift test would pass vacuously")
	}
	for i := 1; i < len(rules); i++ {
		if rules[i-1].Key >= rules[i].Key {
			t.Errorf("rules not sorted by key at %d: %s >= %s", i-1, rules[i-1].Key, rules[i].Key)
		}
	}
	for _, r := range rules {
		if !strings.HasPrefix(r.Key, "promotion.") {
			t.Errorf("rule key %q missing promotion. prefix", r.Key)
		}
		if r.Inputs == "" {
			t.Errorf("rule %q has empty inputs description", r.Key)
		}
		if !r.Effect.Valid() {
			t.Errorf("rule %q has invalid effect %q", r.Key, r.Effect)
		}
	}
	rules2 := Rules()
	for i := range rules {
		if rules[i].Key != rules2[i].Key {
			t.Errorf("Rules() not deterministic at %d: %s vs %s", i, rules[i].Key, rules2[i].Key)
		}
	}
}
