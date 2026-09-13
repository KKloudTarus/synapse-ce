package taint

import "testing"

// TestTwoLabelRulePrecondition is the #1053 acceptance: a two-label sink fires (satisfied) only when a
// source carrying EACH label reaches it; when only one (or neither) reaches, the precondition is UNKNOWN
// (conditionally reachable), never a suppression.
func TestTwoLabelRulePrecondition(t *testing.T) {
	// srcA (label A) -> mid -> sink; srcB (label B) -> mid. Both labels reach the sink.
	both := FlowGraph{
		Sources:      []string{"app.srcA", "app.srcB"},
		Sinks:        []string{"app.sink"},
		Flows:        []Flow{{"app.srcA", "app.mid"}, {"app.srcB", "app.mid"}, {"app.mid", "app.sink"}},
		SourceLabels: map[string]string{"app.srcA": "A", "app.srcB": "B"},
	}
	reached := both.LabelsReaching()["app.sink"]
	if got := EvaluatePrecondition(reached, []string{"A", "B"}); got != PreconditionSatisfied {
		t.Fatalf("both labels reach the sink -> satisfied, got %q (reached=%v)", got, reached)
	}

	// Only label A reaches the sink: the two-label rule does NOT fire, but is NOT suppressed (unknown).
	onlyA := FlowGraph{
		Sources:      []string{"app.srcA"},
		Sinks:        []string{"app.sink"},
		Flows:        []Flow{{"app.srcA", "app.sink"}},
		SourceLabels: map[string]string{"app.srcA": "A"},
	}
	if got := EvaluatePrecondition(onlyA.LabelsReaching()["app.sink"], []string{"A", "B"}); got != PreconditionUnknown {
		t.Fatalf("only label A reaches -> unknown (conditional, never suppress), got %q", got)
	}

	// A sanitizer between srcB and the sink walls label B, so a two-label rule is conditional, not satisfied.
	walled := FlowGraph{
		Sources:      []string{"app.srcA", "app.srcB"},
		Sinks:        []string{"app.sink"},
		Sanitizers:   []string{"app.clean"},
		Flows:        []Flow{{"app.srcA", "app.sink"}, {"app.srcB", "app.clean"}, {"app.clean", "app.sink"}},
		SourceLabels: map[string]string{"app.srcA": "A", "app.srcB": "B"},
	}
	if got := EvaluatePrecondition(walled.LabelsReaching()["app.sink"], []string{"A", "B"}); got != PreconditionUnknown {
		t.Fatalf("a sanitized label-B path must not satisfy the two-label rule, got %q", got)
	}

	// No requires: PreconditionNone (classic single-label behavior, unchanged).
	if got := EvaluatePrecondition(both.LabelsReaching()["app.sink"], nil); got != PreconditionNone {
		t.Fatalf("no requires -> none, got %q", got)
	}
	// A malformed empty-string required label is ignored (cannot force every flow conditional).
	if got := EvaluatePrecondition(both.LabelsReaching()["app.sink"], []string{""}); got != PreconditionNone {
		t.Fatalf("an empty required label must be ignored -> none, got %q", got)
	}
}
