package taintcallgraph

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
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
	got, err := parseCallgraph(buf.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !reflect.DeepEqual(got, g) {
		t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, g)
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
	got, err := parseCallgraph(buf.Bytes())
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

func TestParseRejectsBadProtocol(t *testing.T) {
	// A drifted format must fail closed, not be silently mis-parsed into a partial (taint-false-negative) graph.
	if _, err := parseCallgraph([]byte(`{"protocol_version":"v9.9.9","edges":[]}`)); err == nil {
		t.Error("an unrecognized protocol version must fail closed")
	}
}

func TestParseRejectsBadJSON(t *testing.T) {
	if _, err := parseCallgraph([]byte("{not json")); err == nil {
		t.Error("malformed JSON must fail closed")
	}
}
