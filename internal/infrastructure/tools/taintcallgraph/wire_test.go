package taintcallgraph

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/taint"
)

func TestEncodeParseRoundTrip(t *testing.T) {
	g := &callgraph.Graph{
		Entrypoints: []string{"m.main", "m.Svc.Handle"},
		Edges: []callgraph.Edge{
			{Caller: "m.main", Callees: []string{"m.run"}},
			{Caller: "m.run", Callees: []string{"os/exec.Command"}},
		},
	}
	var buf bytes.Buffer
	if err := EncodeGraph(&buf, g); err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, _, err := parseCallgraph(buf.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !reflect.DeepEqual(got, g) {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, g)
	}
}

func TestEncodeParseCarriesPositions(t *testing.T) {
	// The def-use position side table (#163) must survive the exec-boundary round-trip so a taint finding
	// can cite a file:line instead of only a symbol.
	g := &callgraph.Graph{
		Entrypoints: []string{"m.main"},
		Edges:       []callgraph.Edge{{Caller: "m.main", Callees: []string{"m.dao.Find"}}},
		Positions:   map[string]string{"m.dao.Find": "internal/dao/dao.go:88", "m.main": "main.go:12"},
	}
	var buf bytes.Buffer
	if err := EncodeGraph(&buf, g); err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, _, err := parseCallgraph(buf.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !reflect.DeepEqual(got.Positions, g.Positions) {
		t.Errorf("positions must round-trip:\n got %+v\nwant %+v", got.Positions, g.Positions)
	}
}

func TestEncodeParseEmptyGraph(t *testing.T) {
	// The load-bearing contract (ports.CallGraphBuilder): a SUCCESSFUL build that reached nothing must
	// round-trip to a NON-NIL empty Graph + nil error – the "definitive not-reachable" signal, distinct from
	// a build error (no coverage). reachability.Analyze relies on this distinction to avoid false negatives.
	var buf bytes.Buffer
	if err := EncodeGraph(&buf, &callgraph.Graph{}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, _, err := parseCallgraph(buf.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got == nil {
		t.Fatal("an empty graph must round-trip to a NON-NIL *Graph (definitive not-reachable), not nil")
	}
	if len(got.Edges) != 0 || len(got.Entrypoints) != 0 {
		t.Errorf("empty graph must stay empty: %+v", got)
	}
}

func TestEncodeParseCarriesExecFacts(t *testing.T) {
	// The value-level exec-sink verdict table (D5.4) must survive the exec-boundary round-trip so the
	// coordinator can de-escalate a constant-argv command-injection finding to CWE-88.
	g := &callgraph.Graph{
		Entrypoints: []string{"m.main"},
		Edges:       []callgraph.Edge{{Caller: "m.main", Callees: []string{"os/exec.Command"}}},
	}
	facts := taint.ExecFacts{Funcs: map[string]taint.ExecFuncFacts{
		"m.main":     {SafeSinks: map[string]bool{"os/exec.Command": true}},
		"m.variable": {SafeSinks: map[string]bool{}}, // no safe sink → must NOT ride the wire (keep CWE-78)
	}}
	var buf bytes.Buffer
	if err := EncodeGraphWithFacts(&buf, g, facts); err != nil {
		t.Fatalf("encode: %v", err)
	}
	_, gotFacts, err := parseCallgraph(buf.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := map[string]taint.ExecFuncFacts{"m.main": {SafeSinks: map[string]bool{"os/exec.Command": true}}}
	if !reflect.DeepEqual(gotFacts.Funcs, want) {
		t.Errorf("only proven-safe verdicts must round-trip:\n got %+v\nwant %+v", gotFacts.Funcs, want)
	}
}

// EncodeGraph (no facts) must emit byte-identical output to an empty facts table and no exec_facts key, so
// a graph-only caller is unaffected by the additive field.
func TestEncodeGraphOmitsExecFactsKey(t *testing.T) {
	g := &callgraph.Graph{Edges: []callgraph.Edge{{Caller: "m.main", Callees: []string{"m.run"}}}}
	var a, b bytes.Buffer
	if err := EncodeGraph(&a, g); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := EncodeGraphWithFacts(&b, g, taint.ExecFacts{}); err != nil {
		t.Fatalf("encode with empty facts: %v", err)
	}
	if a.String() != b.String() {
		t.Errorf("EncodeGraph must equal EncodeGraphWithFacts(empty):\n %q\n %q", a.String(), b.String())
	}
	if bytes.Contains(a.Bytes(), []byte("exec_facts")) {
		t.Errorf("no exec_facts key must be emitted for an empty facts table: %s", a.String())
	}
}

func TestParseRejectsBadProtocol(t *testing.T) {
	// A drifted format must fail closed, not be silently mis-parsed into a partial (taint-false-negative) graph.
	if _, _, err := parseCallgraph([]byte(`{"protocol_version":"v9.9.9","edges":[]}`)); err == nil {
		t.Error("an unrecognized protocol version must fail closed")
	}
}

func TestParseRejectsBadJSON(t *testing.T) {
	if _, _, err := parseCallgraph([]byte("{not json")); err == nil {
		t.Error("malformed JSON must fail closed")
	}
}
