package promotion

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/promotion"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestLoadLatestEventsTaintEscalationIsSticky is the #1051 Tier-0 guard against the reversal wiping a taint
// raise: with an attack-path escalation followed by a taint escalation, the taint event is on top of the
// reversal stack and is marked InputsActive=true (sticky), so signal-loss never reverses it and the
// raise-only taint escalation survives even when the attack-path inputs disappear.
func TestLoadLatestEventsTaintEscalationIsSticky(t *testing.T) {
	f := finding.Finding{ID: "f1", Version: 1, Priority: 1}
	store := &fakePromotionStore{events: map[shared.ID][]promotion.PromotionEvent{
		"f1": {
			{ID: "ap-evt", FindingID: "f1", Rule: judgment.RuleRuntimeReachableExposed, Effect: judgment.PromotionEscalate, BeforePriority: 3, AfterPriority: 2},
			{ID: "taint-evt", FindingID: "f1", Rule: judgment.RuleTaintExploitPath, Effect: judgment.PromotionEscalate, BeforePriority: 2, AfterPriority: 1},
		},
	}}
	ev := &Evaluator{promotions: store}

	out, taintApplied, err := ev.loadLatestEvents(context.Background(), "eng", []finding.Finding{f}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !taintApplied["f1"] {
		t.Fatal("a taint escalation event must mark the finding taint-applied")
	}
	pe, ok := out["f1"]
	if !ok {
		t.Fatal("expected a prior escalation for f1")
	}
	// The taint event is on top and sticky: InputsActive=true means Evaluate's signal-loss reversal never
	// fires, so the raise-only taint escalation is never wiped (graph/detections nil are never consulted for
	// a taint top, which is why this runs without them).
	if pe.EventID != "taint-evt" || !pe.InputsActive {
		t.Fatalf("taint top must be sticky (InputsActive=true), got %+v", pe)
	}
}
