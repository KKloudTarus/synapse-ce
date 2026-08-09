package jsreach

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/jssymbols"
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
		Modules:        []modulegraph.Module{mod(module)},
		Edges:          edges,
		Roots:          []string{module},
		SymbolEvidence: &modulegraph.SymbolEvidence{Uses: uses},
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

	reachable, path := analyzeOne(t, a, mustSubject(t, lodashPURL, "template"))
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

	if reachable, _ := analyzeOne(t, a, mustSubject(t, lodashPURL, "template")); reachable {
		t.Fatal("an export nothing imports must not be reachable when every reference was observed")
	}
	// And the exports that ARE imported stay reachable — the negative is specific, not blanket.
	if reachable, _ := analyzeOne(t, a, mustSubject(t, lodashPURL, "merge")); !reachable {
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

	if reachable, _ := analyzeOne(t, a, mustSubject(t, lodashPURL, "merge")); !reachable {
		t.Fatal("an observed property read reaches its export")
	}
	if reachable, _ := analyzeOne(t, a, mustSubject(t, lodashPURL, "template")); reachable {
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

	subject := ports.ReachabilitySubject{FindingID: "f-1", Symbols: []string{mustSubject(t, lodashPURL, "template")}}
	answerable, err := a.answerableSymbolSubjects(context.Background(), "/repo", []ports.ReachabilitySubject{subject})
	if err != nil {
		t.Fatalf("answerable: %v", err)
	}
	if len(answerable) != 0 {
		t.Fatalf("an escaping binding must make the export unanswerable, got %+v", answerable)
	}

	// The export the escaping module DOES read is still answerable, because a positive is always safe.
	positive := ports.ReachabilitySubject{FindingID: "f-2", Symbols: []string{mustSubject(t, lodashPURL, "merge")}}
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
			subject := ports.ReachabilitySubject{FindingID: "f-1", Symbols: []string{mustSubject(t, lodashPURL, "template")}}
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

	// A .js file: the guard must key on the module ACTUALLY containing JSX, not on its extension, since
	// JSX in .js is routine under Babel, CRA and Next.
	graph, result := graphWith("src/App.js",
		[]modulegraph.Edge{namespaceEdge("src/App.js", "React")},
		[]modulegraph.LocalUse{
			{Module: "src/App.js", Local: "React", Property: "useState", Kind: modulegraph.LocalUseProperty},
		})
	graph.SymbolEvidence.JSXModules = []string{"src/App.js"}
	a := symbolAnalyzerFor(t, graph, result, lodashPURL)

	subject := ports.ReachabilitySubject{FindingID: "f-1", Symbols: []string{mustSubject(t, lodashPURL, "createElement")}}
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
	subject := ports.ReachabilitySubject{FindingID: "f-1", Symbols: []string{mustSubject(t, lodashPURL, "template")}}
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

	if _, err := a.Analyze(context.Background(), "/repo", []string{mustSubject(t, lodashPURL, "template")}); !errors.Is(err, shared.ErrValidation) {
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

	subject := ports.ReachabilitySubject{FindingID: "f-1", Symbols: []string{mustSubject(t, lodashPURL, "merge")}}
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
		subject, ok := jssymbols.Subject(test.purl, test.symbol)
		if !ok {
			t.Fatalf("Subject(%q, %q) must be mintable", test.purl, test.symbol)
		}
		purl, symbol, ok := jssymbols.ParseSubject(subject)
		if !ok || purl != test.purl || symbol != test.symbol {
			t.Fatalf("round trip of %q gave (%q, %q, %v)", subject, purl, symbol, ok)
		}
	}
	// The writer is the mirror of the reader: a subject it refuses to mint is one the parser refuses.
	for _, bad := range []struct{ purl, symbol string }{
		{"not-a-purl", "template"}, {"pkg:npm/lodash@1.0.0", ""}, {"pkg:npm/lodash@1.0.0", "a.b"},
		{"pkg:npm/lodash@1.0.0", "with space"}, {"pkg:npm/lodash@1.0.0", "1abc"},
	} {
		if _, ok := jssymbols.Subject(bad.purl, bad.symbol); ok {
			t.Fatalf("Subject(%q, %q) must be refused", bad.purl, bad.symbol)
		}
	}
	for _, malformed := range []string{"pkg:npm/lodash@1.0.0", "#template", "pkg:npm/lodash@1.0.0#", "not-a-purl#x", "pkg:npm/lodash@1.0.0# x"} {
		if _, _, ok := jssymbols.ParseSubject(malformed); ok {
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

// mustSubject mints a Tier-2 subject, failing the test if the fixture is not mintable.
func mustSubject(t *testing.T, purl, symbol string) string {
	t.Helper()
	subject, ok := jssymbols.Subject(purl, symbol)
	if !ok {
		t.Fatalf("fixture subject (%q, %q) is not mintable", purl, symbol)
	}
	return subject
}

// TestAnUnobservedWholeModuleBindingInAnotherModuleBlocksTheNegative is the cross-module regression.
// Module A names one export; module B holds the whole package and never mentions it again. Treating B's
// silence as "no reference" left A's named use as the only evidence, and the verdict came back
// not-reachable for a package B holds in full.
func TestAnUnobservedWholeModuleBindingInAnotherModuleBlocksTheNegative(t *testing.T) {
	t.Parallel()

	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{mod("src/a.ts"), mod("src/b.ts")},
		Edges: []modulegraph.Edge{
			namedEdge("src/a.ts", "merge"),
			namespaceEdge("src/b.ts", "_"), // bound, never referenced again
		},
		Roots:          []string{"src/a.ts", "src/b.ts"},
		SymbolEvidence: &modulegraph.SymbolEvidence{},
	}
	result := jsresolution.Result{}
	for _, edge := range graph.Edges {
		result.Imports = append(result.Imports, jsresolution.ImportResolution{
			From: edge.From, Specifier: edge.Specifier, Kind: edge.Kind,
			Status:  jsresolution.StatusComponent,
			Package: jsresolution.PackageIdentity{Name: "lodash", Version: "4.17.15", PURL: lodashPURL},
		})
	}
	a := symbolAnalyzerFor(t, graph, result, lodashPURL)

	subject := ports.ReachabilitySubject{FindingID: "f-1", Symbols: []string{mustSubject(t, lodashPURL, "template")}}
	answerable, err := a.answerableSymbolSubjects(context.Background(), "/repo", []ports.ReachabilitySubject{subject})
	if err != nil {
		t.Fatalf("answerable: %v", err)
	}
	if len(answerable) != 0 {
		t.Fatal("a whole-module binding nobody enumerated must block the negative, even from another module")
	}
}

// A default-named binding binds the module object for a CommonJS package, so it can reach any export.
func TestDefaultNamedBindingIsWholeModule(t *testing.T) {
	t.Parallel()

	graph, result := graphWith("src/a.ts", []modulegraph.Edge{{
		From: "src/a.ts", Specifier: "lodash", Kind: modulegraph.ImportCommonJS,
		Bindings: []modulegraph.Binding{{Imported: "default", Local: "axios"}},
	}}, []modulegraph.LocalUse{
		{Module: "src/a.ts", Local: "axios", Property: "get", Kind: modulegraph.LocalUseProperty},
	})
	a := symbolAnalyzerFor(t, graph, result, lodashPURL)

	// `get` is observed, so it is reachable...
	if reachable, _ := analyzeOne(t, a, mustSubject(t, lodashPURL, "get")); !reachable {
		t.Fatal("an observed property read of the default binding reaches its export")
	}
	// ...and an export it does NOT name is still answerable, because every reference was enumerated.
	if reachable, _ := analyzeOne(t, a, mustSubject(t, lodashPURL, "post")); reachable {
		t.Fatal("an export no observed read names must not be reachable when all references were seen")
	}
}

// TestIncompleteSymbolEvidenceRefusesWithoutTouchingTheImportGraph: a Tier-2 limitation must refuse
// Tier-2 and nothing else.
func TestIncompleteSymbolEvidenceRefusesWithoutTouchingTheImportGraph(t *testing.T) {
	t.Parallel()

	graph, result := graphWith("src/a.ts", []modulegraph.Edge{namedEdge("src/a.ts", "merge")}, nil)
	graph.SymbolEvidence.Coverage = []modulegraph.CoverageIssue{{
		Kind: modulegraph.CoverageSymbolEvidenceIncomplete, Path: "src/a.ts",
	}}
	a := symbolAnalyzerFor(t, graph, result, lodashPURL)
	if _, err := a.Analyze(context.Background(), "/repo", []string{mustSubject(t, lodashPURL, "template")}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("incomplete symbol evidence must refuse the tier-2 analysis, got %v", err)
	}

	// Symbol evidence that was never collected at all is likewise not a fact about anything.
	graph2, result2 := graphWith("src/a.ts", []modulegraph.Edge{namedEdge("src/a.ts", "merge")}, nil)
	graph2.SymbolEvidence = nil
	b := symbolAnalyzerFor(t, graph2, result2, lodashPURL)
	if _, err := b.Analyze(context.Background(), "/repo", []string{mustSubject(t, lodashPURL, "template")}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("uncollected symbol evidence must refuse the tier-2 analysis, got %v", err)
	}
}

// TestTheTargetIsScannedOnce locks the single-gather contract: the subject filter and the verdict must
// be computed from the SAME snapshot, or a subject admitted as answerable could be decided on evidence
// that changed underneath it.
func TestTheTargetIsScannedOnce(t *testing.T) {
	t.Parallel()

	graph, result := graphWith("src/a.ts", []modulegraph.Edge{namedEdge("src/a.ts", "merge")}, nil)
	result.Complete = true
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "4.17.15", PURL: lodashPURL}}}
	result.DeclaredDependencies = []string{"lodash"}

	counting := &countingScanner{graph: graph}
	a, err := NewSymbolAnalyzer(counting, fakeResolver{result: result}, fakeSBOMs{doc: doc})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	subject := ports.ReachabilitySubject{FindingID: "f-1", Symbols: []string{mustSubject(t, lodashPURL, "merge")}}
	answerable, err := a.answerableSymbolSubjects(context.Background(), "/repo", []ports.ReachabilitySubject{subject})
	if err != nil {
		t.Fatalf("answerable: %v", err)
	}
	if _, err := a.Analyze(context.Background(), "/repo", answerable[0].Symbols); err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if counting.calls != 1 {
		t.Fatalf("the target was scanned %d times; the filter and the verdict must share one snapshot", counting.calls)
	}
}

type countingScanner struct {
	graph modulegraph.Graph
	calls int
}

func (c *countingScanner) Scan(context.Context, string) (modulegraph.Graph, error) {
	c.calls++
	return c.graph, nil
}
