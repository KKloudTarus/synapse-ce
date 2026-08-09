package srcreach

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeScanner struct {
	graph ports.SourceImportGraph
	err   error
	lang  string
}

func (f fakeScanner) ScanImports(context.Context, string) (ports.SourceImportGraph, error) {
	return f.graph, f.err
}
func (f fakeScanner) Lang() string { return f.lang }

func identityCandidates(name string) []string { return []string{name} }

func TestNewValidates(t *testing.T) {
	t.Parallel()
	if _, err := New(nil, identityCandidates); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a nil scanner must be rejected, got %v", err)
	}
	if _, err := New(fakeScanner{lang: "cargo"}, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a nil namer must be rejected, got %v", err)
	}
}

func TestReachableAndNotReachable(t *testing.T) {
	t.Parallel()

	a, err := New(fakeScanner{
		lang:  "cargo",
		graph: ports.SourceImportGraph{ImportedPackages: []string{"serde"}, FilesScanned: 1},
	}, identityCandidates)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	analysis, err := a.Analyze(context.Background(), "/ws", []string{"serde", "unused-crate"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !analysis.Results[0].Reachable {
		t.Fatal("a referenced package must be reachable")
	}
	if analysis.Results[1].Reachable {
		t.Fatal("an unreferenced package must be not-reachable")
	}
	if len(analysis.Results[0].Path) == 0 {
		t.Fatal("a reachable result must carry a proof")
	}
}

// TestUnknownNeverResolvesToUnreachable is the acceptance gate of #414, asserted per language: no input
// may produce an unreachable verdict while an unknown region exists, because an unreachable verdict
// suppresses work.
func TestUnknownNeverResolvesToUnreachable(t *testing.T) {
	t.Parallel()

	for _, lang := range []string{"cargo", "composer", "gem"} {
		lang := lang
		t.Run(lang, func(t *testing.T) {
			t.Parallel()
			a, err := New(fakeScanner{
				lang: lang,
				graph: ports.SourceImportGraph{
					ImportedPackages: []string{"observed"},
					// One unknown region is enough: something could reference the subject invisibly.
					CoverageReasons: []string{"a dynamic construct hides references"},
					FilesScanned:    1,
				},
			}, identityCandidates)
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			analysis, err := a.Analyze(context.Background(), "/ws", []string{"never-referenced"})
			if err == nil {
				t.Fatalf("an unknown region must refuse the analysis, got %+v", analysis)
			}
			if analysis != nil {
				t.Fatalf("a refusal must return no analysis, got %+v", analysis)
			}
		})
	}
}

func TestIncompleteEntrypointDiscoveryYieldsNoVerdict(t *testing.T) {
	t.Parallel()

	// Incomplete discovery must yield unknown with a coverage reason, never a clean unreachable.
	a, err := New(fakeScanner{
		lang: "gem",
		graph: ports.SourceImportGraph{
			ImportedPackages: []string{"rails"},
			CoverageReasons:  []string{"source file budget exceeded; some files were not scanned"},
		},
	}, identityCandidates)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := a.Analyze(context.Background(), "/ws", []string{"rails"}); err == nil {
		t.Fatal("incomplete discovery must refuse the analysis")
	}
}

func TestScanFailureIsNoCoverage(t *testing.T) {
	t.Parallel()

	a, err := New(fakeScanner{lang: "cargo", err: errors.New("scan exploded")}, identityCandidates)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	analysis, err := a.Analyze(context.Background(), "/ws", []string{"serde"})
	if err == nil || analysis != nil {
		t.Fatal("a scan failure must be a no-coverage error with no analysis")
	}
}

func TestGenerousCandidateMatching(t *testing.T) {
	t.Parallel()

	// A dependency referenced under an alternate name must still count: over-matching biases toward
	// reachable, which is safe; under-matching would suppress a real finding.
	a, err := New(fakeScanner{
		lang:  "cargo",
		graph: ports.SourceImportGraph{ImportedPackages: []string{"serde_json"}, FilesScanned: 1},
	}, func(name string) []string { return []string{name, "serde_json"} })
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	analysis, err := a.Analyze(context.Background(), "/ws", []string{"serde-json"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !analysis.Results[0].Reachable {
		t.Fatal("an alternate reference form must still count as a reference")
	}
}

func TestSubjectsAreDeduplicatedAndOrdered(t *testing.T) {
	t.Parallel()

	a, err := New(fakeScanner{
		lang:  "gem",
		graph: ports.SourceImportGraph{ImportedPackages: []string{"rails"}, FilesScanned: 1},
	}, identityCandidates)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	analysis, err := a.Analyze(context.Background(), "/ws", []string{"b", "a", "b", "", "c"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	want := []string{"b", "a", "c"}
	if len(analysis.Results) != len(want) {
		t.Fatalf("got %d results, want %d", len(analysis.Results), len(want))
	}
	for i := range want {
		if analysis.Results[i].Symbol != want[i] {
			t.Fatalf("result[%d] = %q, want %q", i, analysis.Results[i].Symbol, want[i])
		}
	}
}

func TestCancelledContextIsHonored(t *testing.T) {
	t.Parallel()

	a, err := New(fakeScanner{
		lang:  "cargo",
		graph: ports.SourceImportGraph{ImportedPackages: []string{"serde"}, FilesScanned: 1},
	}, identityCandidates)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Analyze(ctx, "/ws", []string{"serde"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled context must abort the analysis, got %v", err)
	}
}
