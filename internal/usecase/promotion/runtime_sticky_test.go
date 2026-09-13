package promotion

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/promotion"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// TestLoadLatestEventsRuntimeEscalationIsSticky is the #1061 hard-bar guard against the reversal wiping a
// runtime-library raise: with an attack-path escalation followed by a runtime-library escalation, the
// runtime event is on top of the reversal stack and is marked InputsActive=true (sticky), so signal-loss
// never reverses it and the raise-only runtime escalation survives even when the attack-path inputs
// disappear. runtimeApplied is derived from the final post-reversal stack, so the raise fires at most once.
func TestLoadLatestEventsRuntimeEscalationIsSticky(t *testing.T) {
	f := finding.Finding{ID: "f1", Version: 1, Priority: 1}
	store := &fakePromotionStore{events: map[shared.ID][]promotion.PromotionEvent{
		"f1": {
			{ID: "ap-evt", FindingID: "f1", Rule: judgment.RuleRuntimeReachableExposed, Effect: judgment.PromotionEscalate, BeforePriority: 3, AfterPriority: 2},
			{ID: "rt-evt", FindingID: "f1", Rule: judgment.RuleRuntimeLibraryLoaded, Effect: judgment.PromotionEscalate, BeforePriority: 2, AfterPriority: 1},
		},
	}}
	ev := &Evaluator{promotions: store}

	out, _, runtimeApplied, err := ev.loadLatestEvents(context.Background(), "eng", []finding.Finding{f}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !runtimeApplied["f1"] {
		t.Fatal("a runtime-library escalation event must mark the finding runtime-applied (fires at most once)")
	}
	pe, ok := out["f1"]
	if !ok {
		t.Fatal("expected a prior escalation for f1")
	}
	// The runtime event is on top and sticky: InputsActive=true means Evaluate's signal-loss reversal never
	// fires, so the raise-only runtime escalation is never wiped (graph/detections nil are never consulted
	// for a runtime top, which is why this runs without them).
	if pe.EventID != "rt-evt" || !pe.InputsActive {
		t.Fatalf("runtime top must be sticky (InputsActive=true), got %+v", pe)
	}
}

// TestLoadLatestEventsRuntimeShieldsLowerEscalation asserts that a sticky runtime top shields a lower,
// non-sticky attack-path escalation from a signal-loss reversal: while the runtime event sits on top with
// permanently-active inputs, the prior returned is the runtime top (InputsActive=true), so Evaluate never
// de-escalates below the runtime-escalated level even when the attack-path detection inputs are gone (graph
// and detections are nil here, i.e. no active inputs). This is the raise-only-safe direction.
func TestLoadLatestEventsRuntimeShieldsLowerEscalation(t *testing.T) {
	f := finding.Finding{ID: "f1", Version: 1, Priority: 1}
	store := &fakePromotionStore{events: map[shared.ID][]promotion.PromotionEvent{
		"f1": {
			{ID: "ap-evt", FindingID: "f1", Rule: judgment.RuleRuntimeReachableExposed, Effect: judgment.PromotionEscalate, BeforePriority: 3, AfterPriority: 2, Inputs: []judgment.PromotionInput{{Kind: judgment.PromotionInputDetection, ID: "det-1"}}},
			{ID: "rt-evt", FindingID: "f1", Rule: judgment.RuleRuntimeLibraryLoaded, Effect: judgment.PromotionEscalate, BeforePriority: 2, AfterPriority: 1},
		},
	}}
	ev := &Evaluator{promotions: store}

	out, _, _, err := ev.loadLatestEvents(context.Background(), "eng", []finding.Finding{f}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	pe := out["f1"]
	if pe.EventID != "rt-evt" || !pe.InputsActive {
		t.Fatalf("runtime top must shield the lower escalation (sticky, InputsActive=true), got %+v", pe)
	}
}
