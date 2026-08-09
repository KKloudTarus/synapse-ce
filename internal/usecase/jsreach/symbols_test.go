package jsreach

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const lodashPURL = "pkg:npm/lodash@4.17.15"

// symbolAnalyzerFor wires a Tier-2 analyzer whose SBOM contains, and whose manifests declare, every purl
// in answerable — the preconditions the analyzer requires before it will answer at all.
func symbolAnalyzerFor(t *testing.T, graph modulegraph.Graph, result jsresolution.Result, answerable ...string) *SymbolAnalyzer {
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

	a, err := NewSymbolAnalyzer(fakeScanner{graph: graph}, fakeResolver{result: result}, fakeSBOMs{doc: doc})
	if err != nil {
		t.Fatalf("new symbol analyzer: %v", err)
	}
	return a
}

// graphWith assembles a one-module graph plus its resolution.
func graphWith(module string, edges []modulegraph.Edge, uses []modulegraph.LocalUse) (modulegraph.Graph, jsresolution.Result) {
	graph := modulegraph.Graph{
		Modules:   []modulegraph.Module{mod(module)},
		Edges:     edges,
		Roots:     []string{module},
		LocalUses: uses,
	}
	result := jsresolution.Result{}
	for _, edge := range edges {
		result.Imports = append(result.Imports, jsresolution.ImportResolution{
			From: edge.From, Specifier: edge.Specifier, Kind: edge.Kind,
			Status:  jsresolution.StatusComponent,
			Package: jsresolution.PackageIdentity{Name: "lodash", Version: "4.17.15", PURL: lodashPURL},
		})
	}
	return graph, result
}

func namedEdge(module, symbol string) modulegraph.Edge {
	return modulegraph.Edge{
		From: module, Specifier: "lodash", Kind: modulegraph.ImportESMStatic,
		Bindings: []modulegraph.Binding{{Imported: symbol, Local: symbol}},
	}
}

func namespaceEdge(module, local string) modulegraph.Edge {
	return modulegraph.Edge{
		From: module, Specifier: "lodash", Kind: modulegraph.ImportESMStatic,
		Bindings: []modulegraph.Binding{{Local: local, Namespace: true}},
	}
}

func analyzeOne(t *testing.T, a *SymbolAnalyzer, subject string) (bool, []string) {
	t.Helper()
	analysis, err := a.Analyze(context.Background(), "/repo", []string{subject})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(analysis.Results) != 1 {
		t.Fatalf("expected one result, got %d", len(analysis.Results))
	}
	return analysis.Results[0].Reachable, analysis.Results[0].Path
}

// TestNamedImportOfTheAffectedExportIsReachable is the positive case: a named import binds one export
// exactly, so reaching it needs no further evidence.
func TestNamedImportOfTheAffectedExportIsReachable(t *testing.T) {
	t.Parallel()

	graph, result := graphWith("src/a.ts", []modulegraph.Edge{namedEdge("src/a.ts", "template")}, nil)
	a := symbolAnalyzerFor(t, graph, result, lodashPURL)

	reachable, path := analyzeOne(t, a, jsresolution.NPMSymbolSubject(lodashPURL, "template"))
	if !reachable {
		t.Fatal("a named import of the affected export is reachable")
	}
	if len(path) == 0 || !strings.Contains(strings.Join(path, " → "), "uses template") {
		t.Fatalf("the proof must name the export that was reached, got %v", path)
	}
}

// TestNamedImportsOfOtherExportsAreNotReachable is the value Tier-2 adds over Tier-1: the package IS
// imported, and the affected export still is not reached.
func TestNamedImportsOfOtherExportsAreNotReachable(t *testing.T) {
	t.Parallel()

	graph, result := graphWith("src/a.ts", []modulegraph.Edge{
		namedEdge("src/a.ts", "merge"),
		namedEdge("src/a.ts", "cloneDeep"),
	}, nil)
	a := symbolAnalyzerFor(t, graph, result, lodashPURL)

	if reachable, _ := analyzeOne(t, a, jsresolution.NPMSymbolSubject(lodashPURL, "template")); reachable {
		t.Fatal("an export nothing imports must not be reachable when every reference was observed")
	}
	// And the exports that ARE imported stay reachable — the negative is specific, not blanket.
	if reachable, _ := analyzeOne(t, a, jsresolution.NPMSymbolSubject(lodashPURL, "merge")); !reachable {
		t.Fatal("an imported export must remain reachable")
	}
}

// TestObservedPropertyReadsNarrowANamespace: a whole-module binding is answerable exactly when every
// reference to its local was an observable property read.
func TestObservedPropertyReadsNarrowANamespace(t *testing.T) {
	t.Parallel()

	graph, result := graphWith("src/a.ts",
		[]modulegraph.Edge{namespaceEdge("src/a.ts", "_")},
		[]modulegraph.LocalUse{
			{Module: "src/a.ts", Local: "_", Property: "merge", Kind: modulegraph.LocalUseProperty},
			{Module: "src/a.ts", Local: "_", Property: "escape", Kind: modulegraph.LocalUseProperty},
		})
	a := symbolAnalyzerFor(t, graph, result, lodashPURL)

	if reachable, _ := analyzeOne(t, a, jsresolution.NPMSymbolSubject(lodashPURL, "merge")); !reachable {
		t.Fatal("an observed property read reaches its export")
	}
	if reachable, _ := analyzeOne(t, a, jsresolution.NPMSymbolSubject(lodashPURL, "template")); reachable {
		t.Fatal("an export no observed property read names must not be reachable")
	}
}

// TestAnEscapingBindingMakesTheSubjectUnanswerable is the safety property. The subject is dropped before
// minting rather than answered, so the weaker Tier-1 judgment stands instead of a false negative.
func TestAnEscapingBindingMakesTheSubjectUnanswerable(t *testing.T) {
	t.Parallel()

	graph, result := graphWith("src/a.ts",
		[]modulegraph.Edge{namespaceEdge("src/a.ts", "_")},
		[]modulegraph.LocalUse{
			{Module: "src/a.ts", Local: "_", Property: "merge", Kind: modulegraph.LocalUseProperty},
			{Module: "src/a.ts", Local: "_", Kind: modulegraph.LocalUseOpaque, Detail: "the binding escapes as a value"},
		})
	a := symbolAnalyzerFor(t, graph, result, lodashPURL)

	subject := ports.ReachabilitySubject{FindingID: "f-1", Symbols: []string{jsresolution.NPMSymbolSubject(lodashPURL, "template")}}
	answerable, err := a.answerableSymbolSubjects(context.Background(), "/repo", []ports.ReachabilitySubject{subject})
	if err != nil {
		t.Fatalf("answerable: %v", err)
	}
	if len(answerable) != 0 {
		t.Fatalf("an escaping binding must make the export unanswerable, got %+v", answerable)
	}

	// The export the escaping module DOES read is still answerable, because a positive is always safe.
	positive := ports.ReachabilitySubject{FindingID: "f-2", Symbols: []string{jsresolution.NPMSymbolSubject(lodashPURL, "merge")}}
	answerable, err = a.answerableSymbolSubjects(context.Background(), "/repo", []ports.ReachabilitySubject{positive})
	if err != nil {
		t.Fatalf("answerable: %v", err)
	}
	if len(answerable) != 1 {
		t.Fatalf("an observed positive stays answerable, got %+v", answerable)
	}
}

// Each of these binds or reaches the whole module, so none of them may leave a symbol answerable as
// not-reached.
func TestWholeModuleFormsAreUnanswerable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		edges []modulegraph.Edge
		uses  []modulegraph.LocalUse
	}{
		{
			name: "re-export republishes every export",
			edges: []modulegraph.Edge{{
				From: "src/a.ts", Specifier: "lodash", Kind: modulegraph.ImportReExport,
				Bindings: []modulegraph.Binding{{Namespace: true}},
			}},
		},
		{
			name: "a bare load binds nothing this scanner can follow",
			edges: []modulegraph.Edge{{
				From: "src/a.ts", Specifier: "lodash", Kind: modulegraph.ImportCommonJS,
			}},
		},
		{
			name: "a default import of a commonjs package is the module object",
			edges: []modulegraph.Edge{{
				From: "src/a.ts", Specifier: "lodash", Kind: modulegraph.ImportESMStatic,
				Bindings: []modulegraph.Binding{{Imported: "default", Local: "_", Default: true}},
			}},
			uses: []modulegraph.LocalUse{
				{Module: "src/a.ts", Local: "_", Kind: modulegraph.LocalUseOpaque, Detail: "indexed with a computed key"},
			},
		},
		{
			name:  "a namespace with no observed reference at all",
			edges: []modulegraph.Edge{namespaceEdge("src/a.ts", "_")},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			graph, result := graphWith("src/a.ts", test.edges, test.uses)
			a := symbolAnalyzerFor(t, graph, result, lodashPURL)
			subject := ports.ReachabilitySubject{FindingID: "f-1", Symbols: []string{jsresolution.NPMSymbolSubject(lodashPURL, "template")}}
			answerable, err := a.answerableSymbolSubjects(context.Background(), "/repo", []ports.ReachabilitySubject{subject})
			if err != nil {
				t.Fatalf("answerable: %v", err)
			}
			if len(answerable) != 0 {
				t.Fatalf("%s must leave the export unanswerable, got %+v", test.name, answerable)
			}
		})
	}
}

// TestJSXModulesCannotNarrowAWholeModuleBinding: JSX desugars into calls on the runtime binding that
// never appear as source tokens, so the visible property reads are not the complete set.
func TestJSXModulesCannotNarrowAWholeModuleBinding(t *testing.T) {
	t.Parallel()

	graph, result := graphWith("src/App.tsx",
		[]modulegraph.Edge{namespaceEdge("src/App.tsx", "React")},
		[]modulegraph.LocalUse{
			{Module: "src/App.tsx", Local: "React", Property: "useState", Kind: modulegraph.LocalUseProperty},
		})
	a := symbolAnalyzerFor(t, graph, result, lodashPURL)

	subject := ports.ReachabilitySubject{FindingID: "f-1", Symbols: []string{jsresolution.NPMSymbolSubject(lodashPURL, "createElement")}}
	answerable, err := a.answerableSymbolSubjects(context.Background(), "/repo", []ports.ReachabilitySubject{subject})
	if err != nil {
		t.Fatalf("answerable: %v", err)
	}
	if len(answerable) != 0 {
		t.Fatal("a whole-module binding in a JSX module must not be narrowed by its visible property reads")
	}
}

// A type-only import and a declaration module never execute, so neither reaches an export at runtime —
// but they must also not be the ONLY evidence, which would leave the package looking unimported.
func TestTypeOnlyAndDeclarationBindingsAreNotRuntimeUses(t *testing.T) {
	t.Parallel()

	graph, result := graphWith("src/a.ts", []modulegraph.Edge{{
		From: "src/a.ts", Specifier: "lodash", Kind: modulegraph.ImportESMStatic, TypeOnly: true,
		Bindings: []modulegraph.Binding{{Imported: "template", Local: "template", TypeOnly: true}},
	}}, nil)
	a := symbolAnalyzerFor(t, graph, result, lodashPURL)

	// No runtime use at all: the package-level question is Tier-1's, so this is unanswerable here
	// rather than answered "not reached".
	subject := ports.ReachabilitySubject{FindingID: "f-1", Symbols: []string{jsresolution.NPMSymbolSubject(lodashPURL, "template")}}
	answerable, err := a.answerableSymbolSubjects(context.Background(), "/repo", []ports.ReachabilitySubject{subject})
	if err != nil {
		t.Fatalf("answerable: %v", err)
	}
	if len(answerable) != 0 {
		t.Fatalf("a type-only import is not a runtime use and cannot answer a symbol query, got %+v", answerable)
	}
}

// TestCoverageIssuesRefuseTheWholeAnalysis: anything unobserved means "no edge" is not proof of absence
// for ANY subject, so the pass returns a no-coverage error and mints nothing.
func TestCoverageIssuesRefuseTheWholeAnalysis(t *testing.T) {
	t.Parallel()

	graph, result := graphWith("src/a.ts", []modulegraph.Edge{namedEdge("src/a.ts", "merge")}, nil)
	graph.Coverage = []modulegraph.CoverageIssue{{Kind: modulegraph.CoverageDynamicRequire, Path: "src/a.ts"}}
	a := symbolAnalyzerFor(t, graph, result, lodashPURL)

	if _, err := a.Analyze(context.Background(), "/repo", []string{jsresolution.NPMSymbolSubject(lodashPURL, "template")}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a coverage issue must refuse the analysis, got %v", err)
	}
}

// A transitive package cannot be answered by a first-party graph — the absence of an import proves
// nothing about a package its parent loads.
func TestTransitivePackagesAreUnanswerable(t *testing.T) {
	t.Parallel()

	graph, result := graphWith("src/a.ts", []modulegraph.Edge{namedEdge("src/a.ts", "merge")}, nil)
	// The purl is in the SBOM but NOT declared as a direct dependency.
	result.Complete = true
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.15", PURL: lodashPURL}}}
	a, err := NewSymbolAnalyzer(fakeScanner{graph: graph}, fakeResolver{result: result}, fakeSBOMs{doc: doc})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	subject := ports.ReachabilitySubject{FindingID: "f-1", Symbols: []string{jsresolution.NPMSymbolSubject(lodashPURL, "merge")}}
	answerable, aerr := a.answerableSymbolSubjects(context.Background(), "/repo", []ports.ReachabilitySubject{subject})
	if aerr != nil {
		t.Fatalf("answerable: %v", aerr)
	}
	if len(answerable) != 0 {
		t.Fatalf("a package that is not a declared direct dependency must be unanswerable, got %+v", answerable)
	}
}

// The subject encoding must round-trip exactly, and a malformed subject must be refused rather than
// half-interpreted into a symbol that can never match.
func TestSymbolSubjectRoundTrips(t *testing.T) {
	t.Parallel()

	for _, test := range []struct{ purl, symbol string }{
		{"pkg:npm/lodash@4.17.15", "template"},
		{"pkg:npm/%40scope%2Fpkg@1.0.0", "method"},
	} {
		subject := jsresolution.NPMSymbolSubject(test.purl, test.symbol)
		purl, symbol, ok := jsresolution.ParseNPMSymbolSubject(subject)
		if !ok || purl != test.purl || symbol != test.symbol {
			t.Fatalf("round trip of %q gave (%q, %q, %v)", subject, purl, symbol, ok)
		}
	}
	for _, malformed := range []string{"pkg:npm/lodash@1.0.0", "#template", "pkg:npm/lodash@1.0.0#", "not-a-purl#x", "pkg:npm/lodash@1.0.0# x"} {
		if _, _, ok := jsresolution.ParseNPMSymbolSubject(malformed); ok {
			t.Fatalf("%q must not parse as a symbol subject", malformed)
		}
	}
}

func TestNewSymbolAnalyzerValidatesDependencies(t *testing.T) {
	t.Parallel()

	if _, err := NewSymbolAnalyzer(nil, fakeResolver{}, fakeSBOMs{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a nil scanner must be rejected, got %v", err)
	}
	if _, err := NewSymbolAnalyzer(fakeScanner{}, nil, fakeSBOMs{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a nil resolver must be rejected, got %v", err)
	}
	if _, err := NewSymbolAnalyzer(fakeScanner{}, fakeResolver{}, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a nil sbom provider must be rejected, got %v", err)
	}
}
