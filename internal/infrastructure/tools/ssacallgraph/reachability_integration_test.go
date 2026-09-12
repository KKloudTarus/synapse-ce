package ssacallgraph

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	domaincg "github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
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

// TestGoReachabilityCorpus makes the checked-in Go fixtures a CI-gated recall contract for the owned
// reachability engine. The generic reachbench reducer owns score semantics; this adapter owns only the
// concrete analyzer invocation and exact-symbol lookup, so future language engines can add their own
// adapters without changing the benchmark's math or label vocabulary.
func TestGoReachabilityCorpus(t *testing.T) {
	corpus := reachbench.DefaultCorpus()
	goCases := make([]reachbench.Case, 0)
	for _, item := range corpus.Cases {
		if item.Language == "go" {
			goCases = append(goCases, item)
		}
	}
	if len(goCases) == 0 {
		t.Fatal("reachability corpus must retain at least one Go fixture")
	}
	corpus.Cases = goCases

	svc, err := reachability.NewService(ownedReachBuilder{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	observations := make([]reachbench.Observation, 0, len(corpus.Cases))
	for _, item := range corpus.Cases {
		dir := filepath.Join("testdata", "reachbench", item.Fixture)
		analysis, err := svc.Analyze(context.Background(), dir, []string{item.Symbol})
		if err != nil {
			t.Fatalf("analyze corpus case %q: %v", item.Name, err)
		}
		if len(analysis.Results) != 1 || analysis.Results[0].Symbol != item.Symbol {
			t.Fatalf("corpus case %q returned wrong result set: %+v", item.Name, analysis.Results)
		}
		label := reachbench.PresentUnreached
		if analysis.Results[0].Reachable {
			label = reachbench.Reachable
		}
		t.Logf("reachbench case=%s symbol=%s observed=%s", item.Name, item.Symbol, label)
		observations = append(observations, reachbench.Observation{Case: item.Name, Label: label})
	}
	report, err := reachbench.Evaluate(corpus, observations)
	if err != nil {
		t.Fatalf("score Go reachability corpus: %v", err)
	}
	for _, score := range report.Languages {
		t.Logf("reachbench %-10s: cases=%d exact=%d exact_accuracy=%.3f positive_precision=%.3f positive_recall=%.3f false_positive_reachable=%d", score.Language, score.Cases, score.Exact, score.ExactAccuracy, score.PositivePrecision, score.PositiveRecall, score.FalsePositiveRise)
	}
	if output := strings.TrimSpace(os.Getenv("SYNAPSE_REACHBENCH_OWNED_REPORT")); output != "" {
		file, err := os.Create(output)
		if err != nil {
			t.Fatalf("create owned reachability report: %v", err)
		}
		if err := reachbench.EncodeReport(file, report); err != nil {
			_ = file.Close()
			t.Fatalf("encode owned reachability report: %v", err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close owned reachability report: %v", err)
		}
	}
	for _, path := range strings.Split(os.Getenv("SYNAPSE_REACHBENCH_BASELINE_REPORTS"), ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatalf("open reachability baseline report %q: %v", path, err)
		}
		baseline, loadErr := reachbench.LoadReport(file)
		_ = file.Close()
		if loadErr != nil {
			t.Fatalf("load reachability baseline report %q: %v", path, loadErr)
		}
		if breaches := reachbench.CheckBaselineParity(report, baseline); len(breaches) > 0 {
			t.Fatalf("owned reachability is below baseline %q: %v", path, breaches)
		}
	}
	if breaches := reachbench.CheckRatchet(report, reachbench.DefaultFloors()); len(breaches) > 0 {
		t.Fatalf("Go reachability recall ratchet regressed: %v", breaches)
	}
}
