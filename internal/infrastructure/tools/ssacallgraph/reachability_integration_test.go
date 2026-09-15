package ssacallgraph

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	domaincg "github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
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

// TestGoBlindConstructCorpusCannotSuppress is the #1138 acceptance fixture. The target symbol is genuinely
// absent from the static path, but a reachable unsafe conversion makes that negative incomplete: the same
// BlindConstructs evidence the production coordinator folds into a Tier-2 claim must make
// ProvedNotReachable false, so this result can never become a suppressing not_reachable.
func TestGoBlindConstructCorpusCannotSuppress(t *testing.T) {
	dir := filepath.Join("testdata", "reachbench", "go_blind_unsafe")
	svc, err := reachability.NewService(ownedReachBuilder{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	analysis, err := svc.Analyze(context.Background(), dir, []string{"blindfixture.vulnerable"})
	if err != nil {
		t.Fatalf("analyze blind corpus: %v", err)
	}
	if len(analysis.Results) != 1 || analysis.Results[0].Reachable {
		t.Fatalf("fixture target must be statically unreached, got %+v", analysis.Results)
	}
	if !contains(analysis.BlindConstructs, "unsafe") {
		t.Fatalf("reachable unsafe surface must taint the negative, got %v", analysis.BlindConstructs)
	}
	claim := judgment.ReachabilityClaim{
		Reachable:          judgment.NotReachable,
		Tier:               judgment.Tier2,
		EntrypointsPresent: len(analysis.Entrypoints) > 0,
		BlindConstructs:    analysis.BlindConstructs,
	}
	if claim.ProvedNotReachable() {
		t.Fatalf("blind Tier-2 negative must not be a suppressing proof: %+v", claim)
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
	// Pin the Go denominator so a removed or relabelled case cannot shrink the corpus into an easier subset
	// that the owned and baseline reports would both share. Changing this is a reviewed ratchet update.
	const expectedGoCases = 7
	if len(goCases) != expectedGoCases {
		t.Fatalf("Go corpus has %d cases, expected %d; update the ratchet only with reviewed corpus changes", len(goCases), expectedGoCases)
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
	for _, entry := range strings.Split(os.Getenv("SYNAPSE_REACHBENCH_BASELINE_REPORTS"), ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// Each entry is "tool=path" (osv-scanner=..., semgrep-ce=...), so the freshly reduced report can be
		// held to that tool's pinned expectation before parity.
		tool, path, ok := strings.Cut(entry, "=")
		if !ok || strings.TrimSpace(tool) == "" || strings.TrimSpace(path) == "" {
			t.Fatalf("baseline report entry %q must be tool=path", entry)
		}
		tool, path = strings.TrimSpace(tool), strings.TrimSpace(path)
		file, err := os.Open(path)
		if err != nil {
			t.Fatalf("open reachability baseline report %q: %v", path, err)
		}
		baseline, loadErr := reachbench.LoadReport(file)
		_ = file.Close()
		if loadErr != nil {
			t.Fatalf("load reachability baseline report %q: %v", path, loadErr)
		}
		// Hold the baseline to its EXACT pinned scorecard, so a silently-degraded OSS run (empty or weakened
		// results while still exiting 0/1) or a corpus edit changes the integers and fails here instead of
		// recording a hollow win. Fails closed on an unpinned tool.
		if breaches := reachbench.CheckBaselineExpectation(baseline, tool, "go"); len(breaches) > 0 {
			t.Fatalf("%s baseline did not reproduce its pinned Go scorecard: %v", tool, breaches)
		}
		if breaches := reachbench.CheckBaselineParity(report, baseline); len(breaches) > 0 {
			t.Fatalf("owned reachability is below baseline %q: %v", path, breaches)
		}
	}
	if breaches := reachbench.CheckRatchet(report, reachbench.DefaultFloors()); len(breaches) > 0 {
		t.Fatalf("Go reachability recall ratchet regressed: %v", breaches)
	}
}
