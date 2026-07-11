package ssacallgraph

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	domaincg "github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
)

func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func hasEdge(g *domaincg.Graph, caller, callee string) bool {
	for _, e := range g.Edges {
		if e.Caller == caller {
			for _, c := range e.Callees {
				if c == callee {
					return true
				}
			}
		}
	}
	return false
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestBuildGraphFunctionEdges(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module cgfixture\n\ngo 1.21\n",
		"main.go": `package main

import "os/exec"

func main() { run("ls") }

func run(name string) { _ = exec.Command(name).Run() }
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Specific edges must exist (the full CHA graph is huge – assert the ones we control).
	if !hasEdge(g, "cgfixture.main", "cgfixture.run") {
		t.Errorf("missing edge cgfixture.main → cgfixture.run (edges=%d)", len(g.Edges))
	}
	if !hasEdge(g, "cgfixture.run", "os/exec.Command") {
		t.Errorf("missing edge cgfixture.run → os/exec.Command (a stdlib sink-shaped call)")
	}
	// main is a first-party reachability root; the unexported run is not.
	if !contains(g.Entrypoints, "cgfixture.main") {
		t.Errorf("cgfixture.main must be an entrypoint; got %v", g.Entrypoints)
	}
	if contains(g.Entrypoints, "cgfixture.run") {
		t.Errorf("unexported cgfixture.run must NOT be an entrypoint")
	}
}

func TestBuildGraphMethodNodeID(t *testing.T) {
	// A method node is "pkg.RecvType.Method" with the receiver pointer stripped – matching the govulncheck
	// builder's convention so taint/reachability node ids align.
	dir := writeModule(t, map[string]string{
		"go.mod": "module mfix\n\ngo 1.21\n",
		"m.go": `package main

type Svc struct{}

func (s *Svc) Handle() { helper() }

func helper() {}

func main() { (&Svc{}).Handle() }
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !hasEdge(g, "mfix.Svc.Handle", "mfix.helper") {
		t.Errorf("missing method edge mfix.Svc.Handle → mfix.helper (entrypoints=%v, edges=%d)", g.Entrypoints, len(g.Edges))
	}
	if !contains(g.Entrypoints, "mfix.Svc.Handle") {
		t.Errorf("exported method (*Svc).Handle should be an entrypoint as mfix.Svc.Handle; got %v", g.Entrypoints)
	}
}

func TestBuildGraphGenericInstanceEdgesSurvive(t *testing.T) {
	// A call chain THROUGH a generic function must NOT be severed. A monomorphized instance (Map[int]) has a
	// nil ssa Pkg + a parameterized name, so without Origin() resolution its in/out edges would silently drop
	// – a taint false-negative. The node id resolves to the un-parameterized origin "genfix.Map" (matching
	// the govulncheck convention), so both edges survive.
	dir := writeModule(t, map[string]string{
		"go.mod": "module genfix\n\ngo 1.21\n",
		"main.go": `package main

func Map[T any](xs []T, f func(T) T) []T {
	out := make([]T, len(xs))
	for i, x := range xs {
		out[i] = f(x)
	}
	return out
}

func id(x int) int { return x }

func main() { _ = Map([]int{1, 2}, id) }
`,
	})
	g, err := BuildGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !hasEdge(g, "genfix.main", "genfix.Map") {
		t.Errorf("edge INTO the generic (genfix.main → genfix.Map) must survive Origin resolution (edges=%d)", len(g.Edges))
	}
	if !hasEdge(g, "genfix.Map", "genfix.id") {
		t.Errorf("edge OUT of the generic (genfix.Map → genfix.id) must survive – a severed chain is a taint false-negative")
	}
}

func TestBuildGraphLoadErrorFailsClosed(t *testing.T) {
	// A package that does not compile must fail closed – a partial graph would silently drop edges (a taint
	// false-negative), so BuildGraph refuses it rather than returning an under-approximation.
	dir := writeModule(t, map[string]string{
		"go.mod":  "module brokenfix\n\ngo 1.21\n",
		"main.go": "package main\nfunc main() { undefinedSymbol() }\n",
	})
	if _, err := BuildGraph(context.Background(), dir); err == nil {
		t.Error("a module with a type error must fail closed, not yield a partial graph")
	}
}
