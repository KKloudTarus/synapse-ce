package callgraph

import (
	"reflect"
	"testing"
)

// chain: main -> a -> b -> vuln; iso (isolated, unreachable); cyc1<->cyc2 reachable from main via a.
func sample() Graph {
	return Graph{
		Entrypoints: []string{"pkg.main"},
		Edges: []Edge{
			{Caller: "pkg.main", Callees: []string{"pkg.a"}},
			{Caller: "pkg.a", Callees: []string{"pkg.b", "pkg.cyc1"}},
			{Caller: "pkg.b", Callees: []string{"dep.vuln"}},
			{Caller: "pkg.cyc1", Callees: []string{"pkg.cyc2"}},
			{Caller: "pkg.cyc2", Callees: []string{"pkg.cyc1"}}, // cycle
			{Caller: "iso.x", Callees: []string{"iso.y"}},       // unreachable island
		},
	}
}

func TestPathTo(t *testing.T) {
	g := sample()
	cases := []struct {
		name, target string
		want         []string
	}{
		{"linear chain to vuln", "dep.vuln", []string{"pkg.main", "pkg.a", "pkg.b", "dep.vuln"}},
		{"entrypoint itself", "pkg.main", []string{"pkg.main"}},
		{"reachable through a cycle", "pkg.cyc2", []string{"pkg.main", "pkg.a", "pkg.cyc1", "pkg.cyc2"}},
		{"unreachable island", "iso.y", nil},
		{"not in graph", "nope.absent", nil},
		{"empty target", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := g.PathTo(tc.target); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("PathTo(%q) = %v, want %v", tc.target, got, tc.want)
			}
		})
	}
}

func TestPathToShortest(t *testing.T) {
	// two paths main->short->t and main->l1->l2->t; BFS must return the shorter.
	g := Graph{
		Entrypoints: []string{"main"},
		Edges: []Edge{
			{Caller: "main", Callees: []string{"short", "l1"}},
			{Caller: "short", Callees: []string{"t"}},
			{Caller: "l1", Callees: []string{"l2"}},
			{Caller: "l2", Callees: []string{"t"}},
		},
	}
	if got := g.PathTo("t"); !reflect.DeepEqual(got, []string{"main", "short", "t"}) {
		t.Errorf("PathTo shortest = %v, want [main short t]", got)
	}
}

func TestReaches(t *testing.T) {
	g := sample()
	if !g.Reaches("dep.vuln") {
		t.Error("dep.vuln must be reachable")
	}
	if g.Reaches("iso.y") {
		t.Error("iso.y (island) must NOT be reachable")
	}
}

func TestReachable(t *testing.T) {
	g := sample()
	got := g.Reachable()
	// entrypoint + everything forward-reachable, NOT the isolated island.
	for _, sym := range []string{"pkg.main", "pkg.a", "pkg.b", "dep.vuln", "pkg.cyc1", "pkg.cyc2"} {
		if !got[sym] {
			t.Errorf("%q must be in the reachable set", sym)
		}
	}
	for _, sym := range []string{"iso.x", "iso.y"} {
		if got[sym] {
			t.Errorf("%q (island) must NOT be in the reachable set", sym)
		}
	}
	if len(got) != 6 {
		t.Errorf("reachable set size = %d, want 6: %v", len(got), got)
	}
}

func TestMultipleEntrypoints(t *testing.T) {
	// a symbol reachable only from the SECOND entrypoint must still be found (proof from any entry).
	g := Graph{
		Entrypoints: []string{"m1", "m2"},
		Edges: []Edge{
			{Caller: "m1", Callees: []string{"x"}},
			{Caller: "m2", Callees: []string{"y"}},
		},
	}
	if got := g.PathTo("y"); !reflect.DeepEqual(got, []string{"m2", "y"}) {
		t.Errorf("PathTo(y) = %v, want [m2 y]", got)
	}
}

func TestEmptyGraph(t *testing.T) {
	var g Graph // zero value
	if g.PathTo("anything") != nil {
		t.Error("empty graph: PathTo must be nil")
	}
	if len(g.Reachable()) != 0 {
		t.Error("empty graph: Reachable must be empty")
	}
}

// TestDuplicateCallerEdgesMerge: a builder may emit a caller's callees split across several Edge entries;
// adjacency merges them, so all targets stay reachable.
func TestDuplicateCallerEdgesMerge(t *testing.T) {
	g := Graph{
		Entrypoints: []string{"main"},
		Edges: []Edge{
			{Caller: "main", Callees: []string{"a"}},
			{Caller: "main", Callees: []string{"b"}}, // same caller, separate edge
		},
	}
	if !g.Reaches("a") || !g.Reaches("b") {
		t.Errorf("both split callees of main must be reachable: %v", g.Reachable())
	}
}

// TestTieBreakEarliestEntrypoint locks the documented tie-break: with two equal-length paths via different
// entrypoints, the path from the EARLIEST entrypoint (Entrypoints order) wins – deterministic.
func TestTieBreakEarliestEntrypoint(t *testing.T) {
	g := Graph{
		Entrypoints: []string{"first", "second"},
		Edges: []Edge{
			{Caller: "first", Callees: []string{"t"}},
			{Caller: "second", Callees: []string{"t"}},
		},
	}
	if got := g.PathTo("t"); !reflect.DeepEqual(got, []string{"first", "t"}) {
		t.Errorf("tie-break PathTo(t) = %v, want [first t] (earliest entrypoint)", got)
	}
}

// TestEmptyNodeIdentitiesDropped: the builder is an untrusted producer; empty caller/callee ids
// must never pollute the graph (no path ending in "", no "" in the reachable set).
func TestEmptyNodeIdentitiesDropped(t *testing.T) {
	g := Graph{
		Entrypoints: []string{"main", ""},
		Edges: []Edge{
			{Caller: "main", Callees: []string{"real", ""}},
			{Caller: "", Callees: []string{"ghost"}},
		},
	}
	if g.Reachable()[""] {
		t.Error(`empty node id must not be in the reachable set`)
	}
	if g.Reaches("ghost") {
		t.Error(`a callee of an empty caller must not be reachable`)
	}
	if !g.Reaches("real") {
		t.Error("the real callee must still be reachable")
	}
}
