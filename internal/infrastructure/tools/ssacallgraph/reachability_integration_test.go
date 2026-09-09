package ssacallgraph

import (
	"context"
	"testing"

	domaincg "github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
)

// ownedReachBuilder adapts the in-process owned go/ssa builder to ports.CallGraphBuilder. The server runs the
// same analysis through the sandboxed synapse-callgraph binary (taintcallgraph.Builder); this exercises the
// owned graph directly against reachability.Service, proving the owned engine drives a correct Tier-2 verdict
// with no third-party call-graph tool.
type ownedReachBuilder struct{}

func (ownedReachBuilder) Build(ctx context.Context, targetRef string) (*domaincg.Graph, error) {
	return BuildGraph(ctx, targetRef)
}

// TestReachabilityServiceOverOwnedBuilder is the D4.3 acceptance: reachability.Service over the owned builder
// proves a reached symbol's path and reports an uncalled symbol as not-reachable, exactly as it would over
// govulncheck, because both emit the same "importPath.Symbol" callgraph.Graph.
func TestReachabilityServiceOverOwnedBuilder(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod": "module cgfixture\n\ngo 1.21\n",
		"main.go": `package main

func main() { reached() }

func reached()   {}
func unreached() {}
`,
	})
	svc, err := reachability.NewService(ownedReachBuilder{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	analysis, err := svc.Analyze(context.Background(), dir, []string{"cgfixture.reached", "cgfixture.unreached"})
	if err != nil {
		t.Fatalf("analyze over owned builder: %v", err)
	}
	byName := map[string]reachability.Result{}
	for _, r := range analysis.Results {
		byName[r.Symbol] = r
	}
	if got := byName["cgfixture.reached"]; !got.Reachable || len(got.Path) == 0 {
		t.Errorf("cgfixture.reached must be reachable from main with a proof path, got %+v", got)
	}
	if got := byName["cgfixture.unreached"]; got.Reachable {
		t.Errorf("cgfixture.unreached is never called and must not be reachable, got %+v", got)
	}
}
