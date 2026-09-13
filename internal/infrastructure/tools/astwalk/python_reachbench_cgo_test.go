//go:build cgo

package astwalk

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	domaincg "github.com/KKloudTarus/synapse-ce/internal/domain/callgraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/pythonprogram"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

// copyFixtureToTemp copies a reachbench fixture's Python sources into a fresh temp directory and returns it.
// The committed fixtures live under testdata/, which enry.IsVendor treats as vendored and the Python source
// walker therefore skips; scanning a temp copy exercises the real extractor over a non-vendored tree while
// keeping the module name (the file's basename) — and thus the canonical symbol id — identical.
func copyFixtureToTemp(t *testing.T, fixture string) string {
	t.Helper()
	src := filepath.Join("testdata", "reachbench", fixture)
	dst := t.TempDir()
	// Copy recursively, preserving the relative tree so a future package-shaped fixture (sibling modules,
	// nested relative imports) is measured with the same module ids as committed, not silently flattened.
	err := filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, body, 0o644)
	})
	if err != nil {
		t.Fatalf("copy fixture %q: %v", fixture, err)
	}
	return dst
}

// pythonReachBuilder adapts the owned Python facts + resolver to ports.CallGraphBuilder, so the generic
// reachability.Service (and thus the reachbench reducer) measures the SAME call-graph reachability a scan
// would, over the real extractor. It owns only the analyzer invocation; the reachbench reducer owns the
// score math and the label vocabulary, exactly as the Go corpus adapter does.
type pythonReachBuilder struct{}

func (pythonReachBuilder) Build(ctx context.Context, targetRef string) (*domaincg.Graph, error) {
	doc, err := PythonFactsFor(ctx, targetRef)
	if err != nil {
		return nil, err
	}
	res, err := pythonprogram.Resolve(doc)
	if err != nil {
		return nil, err
	}
	g := res.Graph
	return &g, nil
}

// TestPythonReachabilityCorpus scores the owned Python reachability engine against the shared reachbench
// corpus (#1049). It reuses the generic reachability.Service reachability math over the real resolver graph:
// a queried symbol reached from an entrypoint is `reachable`, an in-tree symbol not reached is
// `present_unreached`. The recall floor is a monotonic ratchet.
func TestPythonReachabilityCorpus(t *testing.T) {
	corpus := reachbench.DefaultCorpus()
	pyCases := make([]reachbench.Case, 0)
	for _, item := range corpus.Cases {
		if item.Language == "python" {
			pyCases = append(pyCases, item)
		}
	}
	if len(pyCases) == 0 {
		t.Fatal("reachability corpus must retain at least one Python fixture")
	}
	corpus.Cases = pyCases

	svc, err := reachability.NewService(pythonReachBuilder{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	observations := make([]reachbench.Observation, 0, len(corpus.Cases))
	for _, item := range corpus.Cases {
		dir := copyFixtureToTemp(t, item.Fixture)
		// Build the graph once to guard against a silently-wrong symbol id: Analyze echoes the queried symbol
		// whether or not the graph contains it, so an id typo would read as present_unreached and let a
		// negative case pass vacuously. Positions holds every resolved symbol id, so require membership.
		g, err := pythonReachBuilder{}.Build(context.Background(), dir)
		if err != nil {
			t.Fatalf("build corpus case %q: %v", item.Name, err)
		}
		if _, ok := g.Positions[item.Symbol]; !ok {
			t.Fatalf("corpus case %q queries symbol %q the resolved graph does not contain (typo?)", item.Name, item.Symbol)
		}
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
		t.Fatalf("score Python reachability corpus: %v", err)
	}
	for _, score := range report.Languages {
		t.Logf("reachbench %-10s: cases=%d exact=%d exact_accuracy=%.3f positive_precision=%.3f positive_recall=%.3f false_positive_reachable=%d",
			score.Language, score.Cases, score.Exact, score.ExactAccuracy, score.PositivePrecision, score.PositiveRecall, score.FalsePositiveRise)
	}
	if breaches := reachbench.CheckRatchet(report, reachbench.DefaultFloors()); len(breaches) > 0 {
		t.Fatalf("Python reachability recall ratchet regressed: %v", breaches)
	}
	// The recall floor alone would not catch an engine that marks everything reachable (recall would still be
	// 1.0). Pin the discrimination the negative case exists for: exact on every case and zero
	// false-positive-reachable, so a regression that over-reaches the private unreached function fails here.
	var py *reachbench.LanguageScore
	for i := range report.Languages {
		if report.Languages[i].Language == "python" {
			py = &report.Languages[i]
		}
	}
	if py == nil {
		t.Fatal("python language score missing from the report")
	}
	if py.Exact != py.Cases {
		t.Errorf("every Python case must score its exact label: exact=%d of %d", py.Exact, py.Cases)
	}
	if py.FalsePositiveRise != 0 {
		t.Errorf("no Python case may be over-reported reachable: false_positive_reachable=%d", py.FalsePositiveRise)
	}
}
