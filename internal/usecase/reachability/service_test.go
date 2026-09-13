package reachability

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// fakeBuilder returns a fixed graph (or a fixed error to model a no-coverage / un-buildable target).
type fakeBuilder struct {
	g   *callgraph.Graph
	err error
}

func (f fakeBuilder) Build(context.Context, string) (*callgraph.Graph, error) {
	return f.g, f.err
}

// graph: main -> a -> vuln1; vuln2 is an isolated (declared-but-uncalled) symbol.
func sampleGraph() *callgraph.Graph {
	return &callgraph.Graph{
		Entrypoints: []string{"app.main"},
		Edges: []callgraph.Edge{
			{Caller: "app.main", Callees: []string{"app.a"}},
			{Caller: "app.a", Callees: []string{"dep.vuln1"}},
			{Caller: "other.x", Callees: []string{"dep.vuln2"}}, // not reachable from main
		},
	}
}

func TestAnalyze(t *testing.T) {
	svc, err := NewService(fakeBuilder{g: sampleGraph()})
	if err != nil {
		t.Fatal(err)
	}
	a, err := svc.Analyze(context.Background(), "/work", []string{"dep.vuln1", "dep.vuln2", "dep.vuln1", ""})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	// the analysis carries the entrypoints it was measured from (provenance)
	if !reflect.DeepEqual(a.Entrypoints, []string{"app.main"}) {
		t.Errorf("entrypoints = %v, want [app.main]", a.Entrypoints)
	}
	got := a.Results
	// dedup + drop empty -> exactly 2 results, input order preserved
	if len(got) != 2 {
		t.Fatalf("want 2 results (deduped, empty dropped), got %d: %+v", len(got), got)
	}
	// vuln1 reachable WITH a proof path
	if got[0].Symbol != "dep.vuln1" || !got[0].Reachable ||
		!reflect.DeepEqual(got[0].Path, []string{"app.main", "app.a", "dep.vuln1"}) {
		t.Errorf("vuln1 = %+v, want reachable with path [app.main app.a dep.vuln1]", got[0])
	}
	// vuln2 present in the graph but NOT reachable from an entrypoint -> definitive not-reachable, no path
	if got[1].Symbol != "dep.vuln2" || got[1].Reachable || got[1].Path != nil {
		t.Errorf("vuln2 = %+v, want not-reachable with nil path", got[1])
	}
}

func TestAnalyzeNilGraphIsNoCoverage(t *testing.T) {
	// a misbehaving builder returning (nil, nil) must be treated as NO coverage (error), never
	// dereferenced (panic) or read as "nothing reachable".
	svc, _ := NewService(fakeBuilder{g: nil, err: nil})
	a, err := svc.Analyze(context.Background(), "/work", []string{"dep.vuln1"})
	if err == nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil graph must be a no-coverage validation error, got %v", err)
	}
	if a != nil {
		t.Errorf("no analysis on a nil graph, got %+v", a)
	}
}

func TestAnalyzeNoCoverageIsError(t *testing.T) {
	// a build error (un-buildable module / unsupported language) = NO coverage -> error, so the caller
	// falls back to a lower tier and NEVER records a false "not reachable".
	buildErr := errors.New("go: cannot find main module")
	svc, _ := NewService(fakeBuilder{err: buildErr})
	a, err := svc.Analyze(context.Background(), "/work", []string{"dep.vuln1"})
	if err == nil {
		t.Fatal("a build failure must be an error (no coverage), not an empty/not-reachable result")
	}
	if !errors.Is(err, buildErr) {
		t.Errorf("error must wrap the builder error, got %v", err)
	}
	if a != nil {
		t.Errorf("no analysis on a build error, got %+v", a)
	}
}

func TestAnalyzeEmptyGraphIsDefinitiveNotReachable(t *testing.T) {
	// a SUCCESSFUL build with an empty graph = definitive "not reachable" for every symbol (distinct from
	// the no-coverage error case above).
	svc, _ := NewService(fakeBuilder{g: &callgraph.Graph{}})
	a, err := svc.Analyze(context.Background(), "/work", []string{"dep.vuln1"})
	if err != nil {
		t.Fatalf("empty graph is success, not error: %v", err)
	}
	if len(a.Results) != 1 || a.Results[0].Reachable {
		t.Errorf("empty graph -> not reachable, got %+v", a.Results)
	}
}

func TestNewServiceValidates(t *testing.T) {
	if _, err := NewService(nil); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("nil builder must fail validation, got %v", err)
	}
}

func TestAnalyzePropagatesBlindConstructs(t *testing.T) {
	// A graph the builder flagged reflection-blind must carry that into the Analysis so the reachproof
	// coordinator refuses to suppress on any not_reachable it derives (EPIC #1042 #1065).
	g := &callgraph.Graph{Entrypoints: []string{"app.main"}, BlindConstructs: []string{"reflection"}}
	svc, err := NewService(fakeBuilder{g: g})
	if err != nil {
		t.Fatal(err)
	}
	a, err := svc.Analyze(context.Background(), "/work", []string{"dep.vuln"})
	if err != nil {
		t.Fatal(err)
	}
	if len(a.BlindConstructs) != 1 || a.BlindConstructs[0] != "reflection" {
		t.Fatalf("Analysis must carry the graph's blind constructs, got %v", a.BlindConstructs)
	}
}
