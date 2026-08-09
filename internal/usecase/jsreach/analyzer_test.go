package jsreach

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type fakeScanner struct {
	graph modulegraph.Graph
	err   error
}

func (f fakeScanner) Scan(context.Context, string) (modulegraph.Graph, error) { return f.graph, f.err }

type fakeResolver struct {
	result jsresolution.Result
	err    error
}

func (f fakeResolver) Resolve(context.Context, string, modulegraph.Graph, *sbom.SBOM) (jsresolution.Result, error) {
	return f.result, f.err
}

type fakeSBOMs struct {
	doc *sbom.SBOM
	err error
}

func (f fakeSBOMs) SBOMFor(context.Context, string) (*sbom.SBOM, error) { return f.doc, f.err }

func emptySBOM() *sbom.SBOM { return &sbom.SBOM{} }

// mod builds a module entry with the dialect implied by its path.
func mod(path string) modulegraph.Module {
	dialect, _ := modulegraph.DialectForPath(path)
	return modulegraph.Module{Path: path, Dialect: dialect, DeclarationOnly: modulegraph.IsDeclarationPath(path)}
}

// componentImport builds a resolved component import from a module.
func componentImport(from, specifier, purl string) jsresolution.ImportResolution {
	return jsresolution.ImportResolution{
		From: from, Specifier: specifier, Kind: modulegraph.ImportESMStatic,
		Status: jsresolution.StatusComponent,
		Package: jsresolution.PackageIdentity{
			Name: specifier, Version: "1.0.0", PURL: purl,
		},
	}
}

// analyzerFor wires an analyzer whose SBOM contains, and whose first-party manifests declare, every
// purl in answerable — the two preconditions the analyzer requires before it will answer at all.
func analyzerFor(t *testing.T, graph modulegraph.Graph, result jsresolution.Result, answerable ...string) *Analyzer {
	t.Helper()
	result.Complete = true

	doc := &sbom.SBOM{}
	for _, purl := range answerable {
		name, version, ok := jsresolution.ParseNPMPURL(purl)
		if !ok {
			t.Fatalf("test fixture purl %q is not a valid npm purl", purl)
		}
		doc.Components = append(doc.Components, sbom.Component{Name: name, Version: version, PURL: purl})
		result.DeclaredDependencies = append(result.DeclaredDependencies, name)
	}

	a, err := New(fakeScanner{graph: graph}, fakeResolver{result: result}, fakeSBOMs{doc: doc})
	if err != nil {
		t.Fatalf("new analyzer: %v", err)
	}
	return a
}

func TestNewValidatesDependencies(t *testing.T) {
	t.Parallel()

	if _, err := New(nil, fakeResolver{}, fakeSBOMs{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a nil scanner must be rejected, got %v", err)
	}
	if _, err := New(fakeScanner{}, nil, fakeSBOMs{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a nil resolver must be rejected, got %v", err)
	}
	if _, err := New(fakeScanner{}, fakeResolver{}, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a nil sbom provider must be rejected, got %v", err)
	}
}

func TestReachableComponent(t *testing.T) {
	t.Parallel()

	const purl = "pkg:npm/lodash@4.17.21"
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{mod("src/index.ts")},
		Roots:   []string{"src/index.ts"},
	}
	result := jsresolution.Result{Imports: []jsresolution.ImportResolution{
		componentImport("src/index.ts", "lodash", purl),
	}}

	analysis, err := analyzerFor(t, graph, result, purl).Analyze(context.Background(), "/ws", []string{purl})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(analysis.Results) != 1 || !analysis.Results[0].Reachable {
		t.Fatalf("an imported component must be reachable, got %+v", analysis.Results)
	}
	// The proof must end at the exact component and name the importing module.
	path := analysis.Results[0].Path
	if len(path) == 0 || path[len(path)-1] != purl {
		t.Fatalf("proof must end at the component purl, got %v", path)
	}
	if path[0] != "src/index.ts" {
		t.Fatalf("proof must start at the importing module, got %v", path)
	}
}

func TestNotReachableComponent(t *testing.T) {
	t.Parallel()

	// The component is in the SBOM but no first-party module imports it. With a fully observed graph
	// and complete resolution, that is a definitive negative.
	graph := modulegraph.Graph{Modules: []modulegraph.Module{mod("src/index.ts")}, Roots: []string{"src/index.ts"}}
	result := jsresolution.Result{Imports: []jsresolution.ImportResolution{
		componentImport("src/index.ts", "used", "pkg:npm/used@1.0.0"),
	}}

	analysis, err := analyzerFor(t, graph, result, "pkg:npm/used@1.0.0", "pkg:npm/unused@2.0.0").
		Analyze(context.Background(), "/ws", []string{"pkg:npm/unused@2.0.0"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(analysis.Results) != 1 || analysis.Results[0].Reachable {
		t.Fatalf("an unimported component must be not-reachable, got %+v", analysis.Results)
	}
	if len(analysis.Results[0].Path) != 0 {
		t.Fatalf("a negative result carries no proof path, got %v", analysis.Results[0].Path)
	}
}

// TestTypeOnlyImportsAreNotRuntimeEvidence locks a core #401 rule: a type relationship does not survive
// compilation, so it must never make a package reachable.
func TestTypeOnlyImportsAreNotRuntimeEvidence(t *testing.T) {
	t.Parallel()

	const purl = "pkg:npm/some-types@1.0.0"
	tests := []struct {
		name string
		imp  jsresolution.ImportResolution
		mods []modulegraph.Module
	}{
		{
			name: "import type clause",
			imp: func() jsresolution.ImportResolution {
				i := componentImport("src/index.ts", "some-types", purl)
				i.TypeOnly = true
				return i
			}(),
			mods: []modulegraph.Module{mod("src/index.ts")},
		},
		{
			name: "declaration-only import flag",
			imp: func() jsresolution.ImportResolution {
				i := componentImport("src/index.ts", "some-types", purl)
				i.DeclarationOnly = true
				return i
			}(),
			mods: []modulegraph.Module{mod("src/index.ts")},
		},
		{
			name: "import inside a declaration module",
			imp:  componentImport("src/types.d.ts", "some-types", purl),
			mods: []modulegraph.Module{mod("src/types.d.ts")},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			graph := modulegraph.Graph{Modules: test.mods, Roots: []string{test.mods[0].Path}}
			result := jsresolution.Result{Imports: []jsresolution.ImportResolution{test.imp}}

			analysis, err := analyzerFor(t, graph, result, purl).Analyze(context.Background(), "/ws", []string{purl})
			if err != nil {
				t.Fatalf("analyze: %v", err)
			}
			if analysis.Results[0].Reachable {
				t.Fatalf("%s must not establish runtime reachability", test.name)
			}
		})
	}
}

func TestRuntimeCapableImportKinds(t *testing.T) {
	t.Parallel()

	// A literal dynamic import and a CommonJS require both name the package explicitly in the source,
	// so both are runtime evidence.
	for _, kind := range []modulegraph.ImportKind{
		modulegraph.ImportESMStatic, modulegraph.ImportESMDynamic,
		modulegraph.ImportCommonJS, modulegraph.ImportReExport, modulegraph.ImportTypeScriptEqual,
	} {
		kind := kind
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()
			const purl = "pkg:npm/chart.js@4.0.0"
			imp := componentImport("src/index.ts", "chart.js", purl)
			imp.Kind = kind
			graph := modulegraph.Graph{Modules: []modulegraph.Module{mod("src/index.ts")}, Roots: []string{"src/index.ts"}}
			result := jsresolution.Result{Imports: []jsresolution.ImportResolution{imp}}

			analysis, err := analyzerFor(t, graph, result, purl).Analyze(context.Background(), "/ws", []string{purl})
			if err != nil {
				t.Fatalf("analyze: %v", err)
			}
			if !analysis.Results[0].Reachable {
				t.Fatalf("%s must establish runtime reachability", kind)
			}
		})
	}
}

// TestIncompleteCoverageNeverYieldsNotReachable is THE safety gate. Each condition below could hide an
// import, so the analyzer must refuse the whole analysis rather than return Reachable:false, which a
// caller would seal as evidence that a dependency is unused.
func TestIncompleteCoverageNeverYieldsNotReachable(t *testing.T) {
	t.Parallel()

	const purl = "pkg:npm/lodash@4.17.21"
	base := modulegraph.Graph{Modules: []modulegraph.Module{mod("src/index.ts")}, Roots: []string{"src/index.ts"}}

	tests := []struct {
		name     string
		scanner  importScanner
		resolver importResolver
		sboms    sbomProvider
	}{
		{
			name:     "scanner failure",
			scanner:  fakeScanner{err: errors.New("scan exploded")},
			resolver: fakeResolver{result: jsresolution.Result{Complete: true}},
			sboms:    fakeSBOMs{doc: emptySBOM()},
		},
		{
			name: "graph coverage issue",
			scanner: fakeScanner{graph: modulegraph.Graph{
				Modules:  base.Modules,
				Roots:    base.Roots,
				Coverage: []modulegraph.CoverageIssue{{Kind: modulegraph.CoverageDynamicRequire, Path: "src/index.ts"}},
			}},
			resolver: fakeResolver{result: jsresolution.Result{Complete: true}},
			sboms:    fakeSBOMs{doc: emptySBOM()},
		},
		{
			name:     "resolver failure",
			scanner:  fakeScanner{graph: base},
			resolver: fakeResolver{err: errors.New("resolve exploded")},
			sboms:    fakeSBOMs{doc: emptySBOM()},
		},
		{
			name:     "incomplete resolution",
			scanner:  fakeScanner{graph: base},
			resolver: fakeResolver{result: jsresolution.Result{Complete: false}},
			sboms:    fakeSBOMs{doc: emptySBOM()},
		},
		{
			name:     "sbom unavailable",
			scanner:  fakeScanner{graph: base},
			resolver: fakeResolver{result: jsresolution.Result{Complete: true}},
			sboms:    fakeSBOMs{err: errors.New("no sbom")},
		},
		{
			name:     "nil sbom",
			scanner:  fakeScanner{graph: base},
			resolver: fakeResolver{result: jsresolution.Result{Complete: true}},
			sboms:    fakeSBOMs{},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			a, err := New(test.scanner, test.resolver, test.sboms)
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			analysis, err := a.Analyze(context.Background(), "/ws", []string{purl})
			if err == nil {
				t.Fatalf("%s must produce a no-coverage error, got analysis %+v", test.name, analysis)
			}
			if analysis != nil {
				t.Fatalf("a no-coverage error must return no analysis, got %+v", analysis)
			}
		})
	}
}

func TestSubjectHandling(t *testing.T) {
	t.Parallel()

	graph := modulegraph.Graph{Modules: []modulegraph.Module{mod("src/index.ts")}, Roots: []string{"src/index.ts"}}
	result := jsresolution.Result{Imports: []jsresolution.ImportResolution{
		componentImport("src/index.ts", "lodash", "pkg:npm/lodash@4.17.21"),
	}}

	t.Run("input order preserved and duplicates removed", func(t *testing.T) {
		t.Parallel()
		subjects := []string{"pkg:npm/b@1.0.0", "pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0", "pkg:npm/c@1.0.0"}
		analysis, err := analyzerFor(t, graph, result, subjects...).Analyze(context.Background(), "/ws", subjects)
		if err != nil {
			t.Fatalf("analyze: %v", err)
		}
		got := make([]string, 0, len(analysis.Results))
		for _, r := range analysis.Results {
			got = append(got, r.Symbol)
		}
		want := []string{"pkg:npm/b@1.0.0", "pkg:npm/a@1.0.0", "pkg:npm/c@1.0.0"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("subjects = %v, want %v", got, want)
		}
	})

	t.Run("non-npm subject is rejected", func(t *testing.T) {
		t.Parallel()
		// Interpreting a PyPI purl as an npm package would answer a question nobody asked.
		_, err := analyzerFor(t, graph, result).Analyze(context.Background(), "/ws", []string{"pkg:pypi/requests@2.0.0"})
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("a non-npm subject must be a validation error, got %v", err)
		}
	})

	t.Run("malformed subject is rejected", func(t *testing.T) {
		t.Parallel()
		_, err := analyzerFor(t, graph, result).Analyze(context.Background(), "/ws", []string{"lodash@4.17.21"})
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("a malformed subject must be a validation error, got %v", err)
		}
	})

	t.Run("no subjects yields an empty analysis", func(t *testing.T) {
		t.Parallel()
		analysis, err := analyzerFor(t, graph, result).Analyze(context.Background(), "/ws", nil)
		if err != nil {
			t.Fatalf("analyze: %v", err)
		}
		if len(analysis.Results) != 0 {
			t.Fatalf("no subjects means no results, got %+v", analysis.Results)
		}
	})

	t.Run("blank target directory is rejected", func(t *testing.T) {
		t.Parallel()
		_, err := analyzerFor(t, graph, result, "pkg:npm/a@1.0.0").Analyze(context.Background(), "  ", []string{"pkg:npm/a@1.0.0"})
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("a blank directory must be a validation error, got %v", err)
		}
	})
}

func TestProofPathIsShortestAndDeterministic(t *testing.T) {
	t.Parallel()

	const purl = "pkg:npm/lodash@4.17.21"
	// Two routes reach the importer; the shorter one must win, and the answer must not depend on edge
	// order in the graph.
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{mod("src/root.ts"), mod("src/short.ts"), mod("src/a.ts"), mod("src/b.ts"), mod("src/leaf.ts")},
		Edges: []modulegraph.Edge{
			{From: "src/root.ts", To: "src/a.ts", Specifier: "./a", Kind: modulegraph.ImportESMStatic},
			{From: "src/a.ts", To: "src/b.ts", Specifier: "./b", Kind: modulegraph.ImportESMStatic},
			{From: "src/b.ts", To: "src/leaf.ts", Specifier: "./leaf", Kind: modulegraph.ImportESMStatic},
			{From: "src/root.ts", To: "src/short.ts", Specifier: "./short", Kind: modulegraph.ImportESMStatic},
			{From: "src/short.ts", To: "src/leaf.ts", Specifier: "./leaf", Kind: modulegraph.ImportESMStatic},
		},
		Roots: []string{"src/root.ts"},
	}
	result := jsresolution.Result{Imports: []jsresolution.ImportResolution{
		componentImport("src/leaf.ts", "lodash", purl),
	}}

	first, err := analyzerFor(t, graph, result, purl).Analyze(context.Background(), "/ws", []string{purl})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	want := []string{"src/root.ts", "src/short.ts", "src/leaf.ts", "import lodash", purl}
	if !reflect.DeepEqual(first.Results[0].Path, want) {
		t.Fatalf("proof = %v, want the shortest route %v", first.Results[0].Path, want)
	}

	second, err := analyzerFor(t, graph, result, purl).Analyze(context.Background(), "/ws", []string{purl})
	if err != nil {
		t.Fatalf("analyze again: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("repeated analysis of the same input must be identical")
	}
}

func TestProofPathIsCycleSafe(t *testing.T) {
	t.Parallel()

	const purl = "pkg:npm/lodash@4.17.21"
	// A pure cycle has no structural roots at all, so the BFS finds nothing and the direct proof is
	// used. This must terminate rather than loop.
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{mod("src/a.ts"), mod("src/b.ts")},
		Edges: []modulegraph.Edge{
			{From: "src/a.ts", To: "src/b.ts", Specifier: "./b", Kind: modulegraph.ImportESMStatic},
			{From: "src/b.ts", To: "src/a.ts", Specifier: "./a", Kind: modulegraph.ImportESMStatic},
		},
	}
	result := jsresolution.Result{Imports: []jsresolution.ImportResolution{
		componentImport("src/b.ts", "lodash", purl),
	}}

	analysis, err := analyzerFor(t, graph, result, purl).Analyze(context.Background(), "/ws", []string{purl})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	want := []string{"src/b.ts", "import lodash", purl}
	if !reflect.DeepEqual(analysis.Results[0].Path, want) {
		t.Fatalf("a rootless graph must fall back to the direct proof, got %v", analysis.Results[0].Path)
	}
}

func TestProofPathContainsNoHostPathsOrSource(t *testing.T) {
	t.Parallel()

	const purl = "pkg:npm/lodash@4.17.21"
	graph := modulegraph.Graph{Modules: []modulegraph.Module{mod("src/index.ts")}, Roots: []string{"src/index.ts"}}
	result := jsresolution.Result{Imports: []jsresolution.ImportResolution{
		componentImport("src/index.ts", "lodash", purl),
	}}

	analysis, err := analyzerFor(t, graph, result, purl).Analyze(context.Background(), "/ws", []string{purl})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	// The proof is sealed into a judgment, so it must carry only repository-relative paths and package
	// identities — never an absolute host path or source text.
	for _, element := range analysis.Results[0].Path {
		if len(element) > 0 && element[0] == '/' {
			t.Fatalf("proof element %q looks like an absolute host path", element)
		}
	}
}

func TestNonComponentStatusesAreNotEvidence(t *testing.T) {
	t.Parallel()

	// Only an exact component identity can prove reachability. A workspace, builtin or ambiguous
	// resolution names no third-party component.
	const purl = "pkg:npm/lodash@4.17.21"
	for _, status := range []jsresolution.Status{
		jsresolution.StatusWorkspace, jsresolution.StatusBuiltin,
		jsresolution.StatusAmbiguous, jsresolution.StatusUnresolved, jsresolution.StatusLocal,
	} {
		status := status
		t.Run(string(status), func(t *testing.T) {
			t.Parallel()
			imp := componentImport("src/index.ts", "lodash", purl)
			imp.Status = status
			graph := modulegraph.Graph{Modules: []modulegraph.Module{mod("src/index.ts")}, Roots: []string{"src/index.ts"}}
			result := jsresolution.Result{Imports: []jsresolution.ImportResolution{imp}}

			analysis, err := analyzerFor(t, graph, result, purl).Analyze(context.Background(), "/ws", []string{purl})
			if err != nil {
				t.Fatalf("analyze: %v", err)
			}
			if analysis.Results[0].Reachable {
				t.Fatalf("status %q must not prove reachability", status)
			}
		})
	}
}

func TestEntrypointsArePreservedAsProvenance(t *testing.T) {
	t.Parallel()

	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{mod("src/a.ts"), mod("src/b.ts")},
		Roots:   []string{"src/a.ts", "src/b.ts"},
	}
	analysis, err := analyzerFor(t, graph, jsresolution.Result{}, "pkg:npm/x@1.0.0").
		Analyze(context.Background(), "/ws", []string{"pkg:npm/x@1.0.0"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !reflect.DeepEqual(analysis.Entrypoints, []string{"src/a.ts", "src/b.ts"}) {
		t.Fatalf("structural roots must be preserved as provenance, got %v", analysis.Entrypoints)
	}
}

// TestSubjectEncodingVariantStillMatches is the regression for the highest-severity defect found in
// review: the subject and the SBOM component may encode a scoped package differently ("%40scope" versus
// "@scope"). A byte comparison would report EVERY scoped package as not-reachable, which downstream
// becomes an OpenVEX not_affected for a package the source demonstrably imports.
func TestSubjectEncodingVariantStillMatches(t *testing.T) {
	t.Parallel()

	const componentPURL = "pkg:npm/%40babel/traverse@7.22.5"
	const subjectPURL = "pkg:npm/@babel/traverse@7.22.5"

	graph := modulegraph.Graph{Modules: []modulegraph.Module{mod("src/index.ts")}, Roots: []string{"src/index.ts"}}
	imp := componentImport("src/index.ts", "@babel/traverse", componentPURL)
	imp.Package.Name = "@babel/traverse"
	result := jsresolution.Result{
		Imports:              []jsresolution.ImportResolution{imp},
		DeclaredDependencies: []string{"@babel/traverse"},
		Complete:             true,
	}
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "@babel/traverse", Version: "7.22.5", PURL: componentPURL}}}

	a, err := New(fakeScanner{graph: graph}, fakeResolver{result: result}, fakeSBOMs{doc: doc})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	analysis, err := a.Analyze(context.Background(), "/ws", []string{subjectPURL})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !analysis.Results[0].Reachable {
		t.Fatal("an encoding variant of the same identity must still match; a byte comparison would suppress a real finding")
	}
	// The result must be keyed by the CALLER's string, because that is what the coordinator looks up.
	if analysis.Results[0].Symbol != subjectPURL {
		t.Fatalf("result symbol = %q, want the caller's exact subject %q", analysis.Results[0].Symbol, subjectPURL)
	}
}

// TestTransitiveSubjectIsRefused locks the semantic limit of a first-party import graph: a package that
// first-party code cannot import directly is loaded by its parent dependency, so the absence of a
// first-party import proves nothing about it.
func TestTransitiveSubjectIsRefused(t *testing.T) {
	t.Parallel()

	const purl = "pkg:npm/deep-transitive@1.0.0"
	graph := modulegraph.Graph{Modules: []modulegraph.Module{mod("src/index.ts")}, Roots: []string{"src/index.ts"}}
	result := jsresolution.Result{
		Complete: true,
		// The manifest declares only "direct"; the subject is a transitive package.
		DeclaredDependencies: []string{"direct"},
	}
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "deep-transitive", Version: "1.0.0", PURL: purl}}}

	a, err := New(fakeScanner{graph: graph}, fakeResolver{result: result}, fakeSBOMs{doc: doc})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	analysis, err := a.Analyze(context.Background(), "/ws", []string{purl})
	if err == nil {
		t.Fatalf("a transitive subject must be refused, got %+v", analysis)
	}
	if analysis != nil {
		t.Fatalf("a refusal must return no analysis, got %+v", analysis)
	}
}

func TestSubjectAbsentFromTheAnalyzedSBOMIsRefused(t *testing.T) {
	t.Parallel()

	// A subject minted from a DIFFERENT document would silently miss every import and be sealed as
	// not-reachable. It must be refused instead.
	const purl = "pkg:npm/from-another-doc@1.0.0"
	graph := modulegraph.Graph{Modules: []modulegraph.Module{mod("src/index.ts")}, Roots: []string{"src/index.ts"}}
	result := jsresolution.Result{Complete: true, DeclaredDependencies: []string{"from-another-doc"}}

	a, err := New(fakeScanner{graph: graph}, fakeResolver{result: result}, fakeSBOMs{doc: &sbom.SBOM{}})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := a.Analyze(context.Background(), "/ws", []string{purl}); err == nil {
		t.Fatal("a subject absent from the analyzed sbom must be refused")
	}
}

func TestResolutionGraphCoverageIsAlsoAGate(t *testing.T) {
	t.Parallel()

	const purl = "pkg:npm/lodash@4.17.21"
	graph := modulegraph.Graph{Modules: []modulegraph.Module{mod("src/index.ts")}, Roots: []string{"src/index.ts"}}
	// The scanner's own snapshot is clean, but the resolver reports a graph limitation. The domain
	// contract says a caller must consider both.
	result := jsresolution.Result{
		Complete:             true,
		DeclaredDependencies: []string{"lodash"},
		GraphCoverage:        []modulegraph.CoverageIssue{{Kind: modulegraph.CoverageDynamicImport, Path: "src/index.ts"}},
	}
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: purl}}}

	a, err := New(fakeScanner{graph: graph}, fakeResolver{result: result}, fakeSBOMs{doc: doc})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := a.Analyze(context.Background(), "/ws", []string{purl}); err == nil {
		t.Fatal("resolution graph coverage must gate the analysis")
	}
}

func TestBlankAndNonCanonicalSubjectsAreRejected(t *testing.T) {
	t.Parallel()

	graph := modulegraph.Graph{Modules: []modulegraph.Module{mod("src/index.ts")}, Roots: []string{"src/index.ts"}}
	// A subject that is silently dropped becomes a sealed not-reachable in the coordinator, which reads
	// "absent from the result set" as a negative.
	bad := []string{
		"",                        // blank
		"   ",                     // whitespace only
		" pkg:npm/lodash@4.17.21", // leading space: the coordinator would look up the untrimmed form
		"pkg:npm/",                // no name
		"pkg:npm/lodash",          // no version
		"pkg:npm/lodash@",         // empty version
		"PKG:NPM/lodash@4.17.21",  // accepted-then-never-matched if the prefix test folds case
	}
	for _, subject := range bad {
		subject := subject
		t.Run(subject, func(t *testing.T) {
			t.Parallel()
			_, err := analyzerFor(t, graph, jsresolution.Result{}).Analyze(context.Background(), "/ws", []string{subject})
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("subject %q must be a validation error, got %v", subject, err)
			}
		})
	}
}

func TestCancelledContextIsHonored(t *testing.T) {
	t.Parallel()

	const purl = "pkg:npm/lodash@4.17.21"
	graph := modulegraph.Graph{Modules: []modulegraph.Module{mod("src/index.ts")}, Roots: []string{"src/index.ts"}}
	result := jsresolution.Result{Complete: true, DeclaredDependencies: []string{"lodash"}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := analyzerFor(t, graph, result, purl).Analyze(ctx, "/ws", []string{purl})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled context must abort the analysis, got %v", err)
	}
}

func TestProofPathCarriesTheResolvedNameNotTheRawSpecifier(t *testing.T) {
	t.Parallel()

	// A specifier is attacker-controlled source text that would otherwise reach a sealed, hash-chained
	// judgment rationale. The proof must carry the resolved package name, which has been through the
	// domain's strict charset validation.
	const purl = "pkg:npm/lodash@4.17.21"
	graph := modulegraph.Graph{Modules: []modulegraph.Module{mod("src/index.ts")}, Roots: []string{"src/index.ts"}}
	imp := componentImport("src/index.ts", "lodash/\x1b[31mCRITICAL\x07", purl)
	imp.Package.Name = "lodash"
	result := jsresolution.Result{Imports: []jsresolution.ImportResolution{imp}, Complete: true, DeclaredDependencies: []string{"lodash"}}
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: purl}}}

	a, err := New(fakeScanner{graph: graph}, fakeResolver{result: result}, fakeSBOMs{doc: doc})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	analysis, err := a.Analyze(context.Background(), "/ws", []string{purl})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	for _, element := range analysis.Results[0].Path {
		if strings.ContainsAny(element, "\x1b\x07\r\n") {
			t.Fatalf("proof element %q carries control bytes into sealed evidence", element)
		}
	}
}

func TestMultipleImportersPickTheDeterministicSite(t *testing.T) {
	t.Parallel()

	const purl = "pkg:npm/lodash@4.17.21"
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{mod("src/a.ts"), mod("src/b.ts")},
		Roots:   []string{"src/a.ts", "src/b.ts"},
	}
	result := jsresolution.Result{
		Imports: []jsresolution.ImportResolution{
			componentImport("src/b.ts", "lodash", purl),
			componentImport("src/a.ts", "lodash", purl),
			componentImport("src/a.ts", "lodash", purl), // duplicate site
		},
		Complete:             true,
		DeclaredDependencies: []string{"lodash"},
	}
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.21", PURL: purl}}}

	a, err := New(fakeScanner{graph: graph}, fakeResolver{result: result}, fakeSBOMs{doc: doc})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	first, err := a.Analyze(context.Background(), "/ws", []string{purl})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	second, err := a.Analyze(context.Background(), "/ws", []string{purl})
	if err != nil {
		t.Fatalf("analyze again: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("multiple importers must still yield a deterministic proof")
	}
	if first.Results[0].Path[0] != "src/a.ts" {
		t.Fatalf("the sorted-first importer must be chosen, got %v", first.Results[0].Path)
	}
}

func TestMixedReachableAndNotReachableSubjects(t *testing.T) {
	t.Parallel()

	const used = "pkg:npm/used@1.0.0"
	const unused = "pkg:npm/unused@2.0.0"
	graph := modulegraph.Graph{Modules: []modulegraph.Module{mod("src/index.ts")}, Roots: []string{"src/index.ts"}}
	result := jsresolution.Result{Imports: []jsresolution.ImportResolution{componentImport("src/index.ts", "used", used)}}

	analysis, err := analyzerFor(t, graph, result, used, unused).Analyze(context.Background(), "/ws", []string{used, unused})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !analysis.Results[0].Reachable || analysis.Results[1].Reachable {
		t.Fatalf("subjects must be answered independently, got %+v", analysis.Results)
	}
}
