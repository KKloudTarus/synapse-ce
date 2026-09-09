package pyreach

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeScanner struct {
	g   ports.PyImportGraph
	err error
}

func (f fakeScanner) ScanImports(context.Context, string) (ports.PyImportGraph, error) {
	return f.g, f.err
}

// directReader returns a DirectDependencyReader that reports the given names as declared direct
// dependencies (found=true). It is the test double for the manifest guard.
func directReader(names ...string) DirectDependencyReader {
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	return func(context.Context, string) (map[string]bool, bool) { return set, true }
}

func resultFor(a *Analyzer, symbols []string) map[string]bool {
	an, err := a.Analyze(context.Background(), "/x", symbols)
	if err != nil {
		return nil
	}
	out := map[string]bool{}
	for _, r := range an.Results {
		out[r.Symbol] = r.Reachable
	}
	return out
}

func TestAnalyzeImportReachability(t *testing.T) {
	a, err := New(fakeScanner{g: ports.PyImportGraph{
		ImportedModules:   []string{"requests", "yaml", "PIL"}, // PyYAML→yaml, Pillow→PIL (case-insensitive)
		FirstPartyModules: []string{"app"},
	}}, directReader("requests", "pyyaml", "pillow", "jinja2"))
	if err != nil {
		t.Fatal(err)
	}
	got := resultFor(a, []string{"requests", "PyYAML", "Pillow", "jinja2"})
	if !got["requests"] {
		t.Error("requests is imported → reachable")
	}
	if !got["PyYAML"] {
		t.Error("PyYAML imports as yaml → reachable (curated mapping)")
	}
	if !got["Pillow"] {
		t.Error("Pillow imports as PIL → reachable (curated + case-insensitive)")
	}
	if got["jinja2"] {
		t.Error("jinja2 is NOT imported → not_reachable (dead dependency)")
	}
}

func TestAnalyzeDynamicImportsIsNoCoverage(t *testing.T) {
	a, _ := New(fakeScanner{g: ports.PyImportGraph{ImportedModules: []string{"requests"}, DynamicImports: true}}, directReader("jinja2"))
	if _, err := a.Analyze(context.Background(), "/x", []string{"jinja2"}); err == nil {
		t.Fatal("dynamic imports must yield a no-coverage error (never a false not_reachable)")
	}
}

func TestAnalyzeScanErrorIsNoCoverage(t *testing.T) {
	a, _ := New(fakeScanner{err: errors.New("no python")}, directReader("jinja2"))
	if _, err := a.Analyze(context.Background(), "/x", []string{"jinja2"}); err == nil {
		t.Fatal("a scan error must propagate as no-coverage")
	}
}

// Partially-unscanned first-party source (an unreadable entry, a byte-truncated file, or the file-count cap)
// must yield a no-coverage error, never a false not_reachable: an import in the unseen region would make
// "not imported" wrong. This matches the Rust/PHP/Ruby Complete() and JS Coverage refusals.
func TestAnalyzeCoverageDegradedIsNoCoverage(t *testing.T) {
	a, _ := New(fakeScanner{g: ports.PyImportGraph{ImportedModules: []string{"requests"}, FirstPartyModules: []string{"app"}, CoverageDegraded: true}}, directReader("jinja2"))
	if _, err := a.Analyze(context.Background(), "/x", []string{"jinja2"}); err == nil {
		t.Fatal("degraded coverage must yield a no-coverage error (never a false not_reachable)")
	}
}

// A subject that is NOT a declared direct dependency must yield a no-coverage error, never a false
// not_reachable — a transitive package is loaded by its parent, so a first-party import scan cannot prove it
// unused. This is the review-verified gap that made defaulting Python Tier-1 ON unsafe before this guard.
func TestAnalyzeTransitiveSubjectIsNoCoverage(t *testing.T) {
	a, _ := New(fakeScanner{g: ports.PyImportGraph{ImportedModules: []string{"requests"}, FirstPartyModules: []string{"app"}}}, directReader("requests"))
	if _, err := a.Analyze(context.Background(), "/x", []string{"jinja2"}); err == nil {
		t.Fatal("a transitive (non-direct) subject must be no-coverage, not a false not_reachable")
	}
	// The direct subject alone still resolves.
	if got := resultFor(a, []string{"requests"}); !got["requests"] {
		t.Error("a declared direct + imported package is still reachable")
	}
}

// No declaration manifest → direct deps unknown → refuse (no coverage), never answer.
func TestAnalyzeNoManifestIsNoCoverage(t *testing.T) {
	a, _ := New(fakeScanner{g: ports.PyImportGraph{ImportedModules: []string{"requests"}}}, func(context.Context, string) (map[string]bool, bool) { return nil, false })
	if _, err := a.Analyze(context.Background(), "/x", []string{"requests"}); err == nil {
		t.Fatal("a missing manifest must yield a no-coverage error")
	}
}

func TestImportCandidates(t *testing.T) {
	cases := map[string][]string{ // dist → a candidate that MUST be present
		"PyYAML":          {"yaml"},
		"scikit-learn":    {"sklearn"},
		"requests":        {"requests"},
		"python-dateutil": {"dateutil"},
		"foo-bar":         {"foo_bar", "foobar"}, // normalized fallbacks
	}
	for dist, wants := range cases {
		cands := ImportCandidates(dist)
		set := map[string]bool{}
		for _, c := range cands {
			set[c] = true
		}
		for _, w := range wants {
			if !set[w] {
				t.Errorf("ImportCandidates(%q) = %v, must include %q", dist, cands, w)
			}
		}
	}
	if ImportCandidates("") != nil {
		t.Error("empty dist → nil candidates")
	}
}
