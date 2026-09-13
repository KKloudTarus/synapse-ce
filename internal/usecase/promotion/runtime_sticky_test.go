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

// TestLoadLatestEventsSignalLossNeverWipesRuntimeAbove is the Codex-flagged regression: a persisted
// signal-loss event that references an OLDER attack-path escalation must not wipe a NEWER runtime-library
// escalation sitting above it on the reversal stack. Replaying attack-path escalate -> runtime escalate ->
// signal-loss(ref attack-path) must leave the runtime escalation on the stack (runtimeApplied stays true,
// the top stays the runtime event), so its raise-only / at-most-once property survives.
func TestLoadLatestEventsSignalLossNeverWipesRuntimeAbove(t *testing.T) {
	f := finding.Finding{ID: "f1", Version: 1, Priority: 1}
	store := &fakePromotionStore{events: map[shared.ID][]promotion.PromotionEvent{
		"f1": {
			{ID: "ap-evt", FindingID: "f1", Rule: judgment.RuleRuntimeReachableExposed, Effect: judgment.PromotionEscalate, BeforePriority: 3, AfterPriority: 2},
			{ID: "rt-evt", FindingID: "f1", Rule: judgment.RuleRuntimeLibraryLoaded, Effect: judgment.PromotionEscalate, BeforePriority: 2, AfterPriority: 1},
			// A stale/external signal-loss referencing the OLDER attack-path event. It must remove only that
			// event, never the runtime event above it.
			{ID: "sl-evt", FindingID: "f1", Rule: judgment.RuleCorroboratingSignalLoss, Effect: judgment.PromotionDeescalate, Inputs: []judgment.PromotionInput{{Kind: judgment.PromotionInputPrior, ID: "ap-evt"}}},
		},
	}}
	ev := &Evaluator{promotions: store}

	out, _, runtimeApplied, err := ev.loadLatestEvents(context.Background(), "eng", []finding.Finding{f}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !runtimeApplied["f1"] {
		t.Fatal("signal loss on the older attack-path event must NOT wipe the runtime escalation (still applied)")
	}
	if pe := out["f1"]; pe.EventID != "rt-evt" || !pe.InputsActive {
		t.Fatalf("runtime escalation must survive the signal-loss pop, got %+v", pe)
	}
}

// TestLoadLatestEventsSignalLossCannotPopStickyDirectly guards the other pop path: a signal-loss event that
// references the sticky runtime escalation ITSELF must not remove it (a sticky raise-only escalation is
// never reversed by signal loss). The normal evaluator never emits such an event, but a stale/external one
// must not de-escalate a raise-only signal.
func TestLoadLatestEventsSignalLossCannotPopStickyDirectly(t *testing.T) {
	f := finding.Finding{ID: "f1", Version: 1, Priority: 1}
	store := &fakePromotionStore{events: map[shared.ID][]promotion.PromotionEvent{
		"f1": {
			{ID: "rt-evt", FindingID: "f1", Rule: judgment.RuleRuntimeLibraryLoaded, Effect: judgment.PromotionEscalate, BeforePriority: 2, AfterPriority: 1},
			{ID: "sl-evt", FindingID: "f1", Rule: judgment.RuleCorroboratingSignalLoss, Effect: judgment.PromotionDeescalate, Inputs: []judgment.PromotionInput{{Kind: judgment.PromotionInputPrior, ID: "rt-evt"}}},
		},
	}}
	ev := &Evaluator{promotions: store}

	out, _, runtimeApplied, err := ev.loadLatestEvents(context.Background(), "eng", []finding.Finding{f}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !runtimeApplied["f1"] {
		t.Fatal("a signal-loss referencing the sticky runtime escalation must not pop it (still applied)")
	}
	if pe := out["f1"]; pe.EventID != "rt-evt" || !pe.InputsActive {
		t.Fatalf("sticky runtime escalation must survive a direct signal-loss reference, got %+v", pe)
	}
}
