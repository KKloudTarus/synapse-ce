//go:build cgo

package astwalk

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

// jsResolveFixture copies a reachbench fixture's JS sources into a fresh temp dir (testdata/ is treated as
// vendored by the source walker, so it must be scanned from a non-vendored tree, keeping the extension-less
// module names — and thus the canonical symbol ids — identical), extracts facts, and resolves the call graph.
func jsResolveFixture(t *testing.T, fixture string) jsprogram.Resolution {
	t.Helper()
	src := filepath.Join("testdata", "reachbench", fixture)
	dst := t.TempDir()
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
	doc, err := JsFactsFor(context.Background(), dst)
	if err != nil {
		t.Fatalf("extract js facts for %q: %v", fixture, err)
	}
	res, err := jsprogram.Resolve(doc)
	if err != nil {
		t.Fatalf("resolve js facts for %q: %v", fixture, err)
	}
	return res
}

// jsCorpusLabel is the raise-only labeling the owned JS engine reports for a queried symbol. A proven call
// path is reachable. Absence of a path is present_unreached ONLY when the resolution is Complete (every call
// resolved over a fully-parsed tree, no dynamic-dispatch gap); when it is incomplete the honest answer is
// no_analysis, never a negative. This is the "every dynamic-dispatch construct forces raise-only/no_analysis"
// property (EPIC #1042 3.4): a computed member, eval, dynamic import, or callback escape leaves the symbol
// no_analysis rather than falsely present_unreached.
func jsCorpusLabel(res jsprogram.Resolution, symbol string) reachbench.Label {
	if res.Graph.Reaches(symbol) {
		return reachbench.Reachable
	}
	if !res.Complete {
		return reachbench.NoAnalysis
	}
	return reachbench.PresentUnreached
}

// TestJSReachabilityCorpus scores the owned JS/TS interprocedural call-graph resolver (jsprogram.Resolve)
// against the shared reachbench corpus (#1058). It measures cross-function, transitive, cross-module, and
// receiver-typed method reachability, and pins that every dynamic-dispatch construct yields no_analysis, not
// a false negative.
func TestJSReachabilityCorpus(t *testing.T) {
	corpus := reachbench.DefaultCorpus()
	jsCases := make([]reachbench.Case, 0)
	for _, item := range corpus.Cases {
		if item.Language == "javascript" {
			jsCases = append(jsCases, item)
		}
	}
	if len(jsCases) == 0 {
		t.Fatal("reachability corpus must retain at least one JavaScript fixture")
	}
	// Pin the JS denominator so a removed or relabelled case cannot shrink the corpus into an easier subset.
	const expectedJSCases = 17
	if len(jsCases) != expectedJSCases {
		t.Fatalf("JS corpus has %d cases, expected %d; update the ratchet only with reviewed corpus changes", len(jsCases), expectedJSCases)
	}
	corpus.Cases = jsCases

	observations := make([]reachbench.Observation, 0, len(corpus.Cases))
	for _, item := range corpus.Cases {
		res := jsResolveFixture(t, item.Fixture)
		// Guard against a silently-wrong symbol id: a typo would read as present_unreached/no_analysis and let
		// a case pass vacuously. Every queried symbol must exist in the resolved graph.
		if _, ok := res.Graph.Positions[item.Symbol]; !ok {
			t.Fatalf("corpus case %q queries symbol %q the resolved graph does not contain (typo?)", item.Name, item.Symbol)
		}
		label := jsCorpusLabel(res, item.Symbol)
		t.Logf("reachbench case=%s symbol=%s observed=%s complete=%v", item.Name, item.Symbol, label, res.Complete)
		observations = append(observations, reachbench.Observation{Case: item.Name, Label: label})
	}
	report, err := reachbench.Evaluate(corpus, observations)
	if err != nil {
		t.Fatalf("score JS reachability corpus: %v", err)
	}
	for _, score := range report.Languages {
		t.Logf("reachbench %-10s: cases=%d exact=%d exact_accuracy=%.3f positive_precision=%.3f positive_recall=%.3f false_positive_reachable=%d",
			score.Language, score.Cases, score.Exact, score.ExactAccuracy, score.PositivePrecision, score.PositiveRecall, score.FalsePositiveRise)
	}
	if breaches := reachbench.CheckRatchet(report, reachbench.DefaultFloors()); len(breaches) > 0 {
		t.Fatalf("JS reachability recall ratchet regressed: %v", breaches)
	}
	// The recall floor alone would not catch an engine that marks everything reachable. Pin exactness and
	// zero false-positive-reachable so a regression that over-reaches an unreached or dynamic case fails here.
	var js *reachbench.LanguageScore
	for i := range report.Languages {
		if report.Languages[i].Language == "javascript" {
			js = &report.Languages[i]
		}
	}
	if js == nil {
		t.Fatal("javascript language score missing from the report")
	}
	if js.Exact != js.Cases {
		t.Errorf("every JS case must score its exact label: exact=%d of %d", js.Exact, js.Cases)
	}
	if js.FalsePositiveRise != 0 {
		t.Errorf("no JS case may be over-reported reachable: false_positive_reachable=%d", js.FalsePositiveRise)
	}
}
