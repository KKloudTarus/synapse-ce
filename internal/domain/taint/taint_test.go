package taint

import (
	"reflect"
	"testing"
)

func TestVulnerabilitiesDirectAndMultiHop(t *testing.T) {
	g := FlowGraph{
		Sources: []string{"http.Param"},
		Sinks:   []string{"db.Query"},
		Flows: []Flow{
			{From: "http.Param", To: "app.handler"},
			{From: "app.handler", To: "app.build"},
			{From: "app.build", To: "db.Query"},
		},
	}
	got := g.Vulnerabilities()
	if len(got) != 1 {
		t.Fatalf("want 1 taint path, got %d: %+v", len(got), got)
	}
	want := TaintPath{Source: "http.Param", Sink: "db.Query", Path: []string{"http.Param", "app.handler", "app.build", "db.Query"}}
	if !reflect.DeepEqual(got[0], want) {
		t.Errorf("taint path = %+v, want %+v", got[0], want)
	}
	if !g.Vulnerable() {
		t.Error("graph must be Vulnerable()")
	}
}

func TestSanitizerIsAWall(t *testing.T) {
	// http.Param -> sanitize.Escape -> db.Query: the sanitizer neutralizes the flow -> NOT vulnerable.
	g := FlowGraph{
		Sources:    []string{"http.Param"},
		Sinks:      []string{"db.Query"},
		Sanitizers: []string{"sanitize.Escape"},
		Flows: []Flow{
			{From: "http.Param", To: "sanitize.Escape"},
			{From: "sanitize.Escape", To: "db.Query"},
		},
	}
	if v := g.Vulnerabilities(); len(v) != 0 {
		t.Fatalf("a sanitized flow must not be a vulnerability, got %+v", v)
	}
	if g.Vulnerable() {
		t.Error("sanitized graph must not be Vulnerable()")
	}
}

func TestMixedSanitizedAndCleanPaths(t *testing.T) {
	// One sink is reachable BOTH directly (tainted) and via a sanitizer; the direct path makes it
	// vulnerable. A second sink is reachable ONLY through a sanitizer -> clean.
	g := FlowGraph{
		Sources:    []string{"src"},
		Sinks:      []string{"sink.A", "sink.B"},
		Sanitizers: []string{"san"},
		Flows: []Flow{
			{From: "src", To: "sink.A"}, // tainted -> A vulnerable
			{From: "src", To: "san"},    // also flows into a sanitizer...
			{From: "san", To: "sink.A"}, //...which would clean A (but the direct path already taints it)
			{From: "san", To: "sink.B"}, // B only reachable past the sanitizer -> clean
		},
	}
	got := g.Vulnerabilities()
	if len(got) != 1 || got[0].Sink != "sink.A" {
		t.Fatalf("want exactly sink.A vulnerable (B is sanitized), got %+v", got)
	}
}

func TestSourceIsSink(t *testing.T) {
	g := FlowGraph{Sources: []string{"x"}, Sinks: []string{"x"}}
	got := g.Vulnerabilities()
	if len(got) != 1 || !reflect.DeepEqual(got[0].Path, []string{"x"}) {
		t.Fatalf("a source that is itself a sink is a length-1 finding, got %+v", got)
	}
	// but if x is also a sanitizer, it's neutralized
	g.Sanitizers = []string{"x"}
	if g.Vulnerable() {
		t.Error("a sanitizer source-sink must not be vulnerable")
	}
}

func TestCycleSafe(t *testing.T) {
	g := FlowGraph{
		Sources: []string{"src"},
		Sinks:   []string{"sink"},
		Flows: []Flow{
			{From: "src", To: "a"},
			{From: "a", To: "b"},
			{From: "b", To: "a"}, // cycle a<->b
			{From: "b", To: "sink"},
		},
	}
	got := g.Vulnerabilities()
	if len(got) != 1 || got[0].Sink != "sink" {
		t.Fatalf("cycle must not loop; sink must be found, got %+v", got)
	}
}

func TestDeterministicSorted(t *testing.T) {
	// two sources each reaching two sinks -> output sorted by (source, sink), stable across runs.
	g := FlowGraph{
		Sources: []string{"s2", "s1"},
		Sinks:   []string{"k2", "k1"},
		Flows: []Flow{
			{From: "s1", To: "k1"}, {From: "s1", To: "k2"},
			{From: "s2", To: "k1"}, {From: "s2", To: "k2"},
		},
	}
	a := g.Vulnerabilities()
	b := g.Vulnerabilities()
	if !reflect.DeepEqual(a, b) {
		t.Fatal("output must be deterministic")
	}
	order := make([]string, len(a))
	for i, tp := range a {
		order[i] = tp.Source + "->" + tp.Sink
	}
	want := []string{"s1->k1", "s1->k2", "s2->k1", "s2->k2"}
	if !reflect.DeepEqual(order, want) {
		t.Errorf("order = %v, want sorted %v", order, want)
	}
}

func TestDuplicateSourceDeduped(t *testing.T) {
	// a builder may emit the same source symbol twice; the finding must not be duplicated.
	g := FlowGraph{Sources: []string{"s", "s", "s"}, Sinks: []string{"k"}, Flows: []Flow{{From: "s", To: "k"}}}
	if got := g.Vulnerabilities(); len(got) != 1 {
		t.Fatalf("duplicate sources must yield ONE finding, got %d: %+v", len(got), got)
	}
}

func TestWitnessIsEarliestFlowOrder(t *testing.T) {
	// two equal-length clean paths src->p1->k and src->p2->k: the witness is the one via the EARLIER Flow
	// (deterministic, so the explainable proof path is stable across runs).
	g := FlowGraph{
		Sources: []string{"src"},
		Sinks:   []string{"k"},
		Flows: []Flow{
			{From: "src", To: "p1"}, // p1 inserted first -> wins the tie
			{From: "src", To: "p2"},
			{From: "p1", To: "k"},
			{From: "p2", To: "k"},
		},
	}
	got := g.Vulnerabilities()
	if len(got) != 1 || !reflect.DeepEqual(got[0].Path, []string{"src", "p1", "k"}) {
		t.Fatalf("witness must be the earliest-flow-order path [src p1 k], got %+v", got)
	}
}

func TestEmpty(t *testing.T) {
	if (FlowGraph{}).Vulnerable() {
		t.Error("empty graph is not vulnerable")
	}
	// sources but no sinks, and sinks but no flow – both non-vulnerable
	if (FlowGraph{Sources: []string{"s"}, Flows: []Flow{{From: "s", To: "x"}}}).Vulnerable() {
		t.Error("no sink -> not vulnerable")
	}
}
