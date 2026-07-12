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
	}})
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
	a, _ := New(fakeScanner{g: ports.PyImportGraph{ImportedModules: []string{"requests"}, DynamicImports: true}})
	if _, err := a.Analyze(context.Background(), "/x", []string{"jinja2"}); err == nil {
		t.Fatal("dynamic imports must yield a no-coverage error (never a false not_reachable)")
	}
}

func TestAnalyzeScanErrorIsNoCoverage(t *testing.T) {
	a, _ := New(fakeScanner{err: errors.New("no python")})
	if _, err := a.Analyze(context.Background(), "/x", []string{"jinja2"}); err == nil {
		t.Fatal("a scan error must propagate as no-coverage")
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
