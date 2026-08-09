package jsresolve

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// docWith builds an SBOM fixture from npm PURLs, mirroring the repository's PURL convention
// (a scoped package encodes its leading "@" as %40).
func docWith(purls ...string) *sbom.SBOM {
	doc := &sbom.SBOM{}
	for _, p := range purls {
		doc.Components = append(doc.Components, sbom.Component{PURL: p})
	}
	return doc
}

// resolveWithSBOM scans a single external specifier from src/index.ts against doc.
func resolveWithSBOM(t *testing.T, specifier string, doc *sbom.SBOM) jsresolution.ImportResolution {
	t.Helper()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "app", "version": "1.0.0"})
	graph := graphWithExternal("src/index.ts", specifier)

	result, err := NewResolver().Resolve(context.Background(), root, graph, doc)
	if err != nil {
		t.Fatalf("resolve %q: %v", specifier, err)
	}
	got := resolutionsBySpecifier(result.Imports)[specifier]
	if got.Specifier != specifier {
		t.Fatalf("no resolution for %q: %+v", specifier, result.Imports)
	}
	return got
}

func TestParseNPMPURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		purl        string
		wantName    string
		wantVersion string
		wantOK      bool
	}{
		{name: "plain package", purl: "pkg:npm/lodash@4.17.21", wantName: "lodash", wantVersion: "4.17.21", wantOK: true},
		{name: "scoped package", purl: "pkg:npm/%40scope/pkg@1.2.3", wantName: "@scope/pkg", wantVersion: "1.2.3", wantOK: true},
		// The component's OWN casing is preserved: npm hosts distinct packages whose names differ only in
		// case (JSONStream and jsonstream), so folding here would let one package's purl be attached to
		// another package's import.
		{name: "mixed case is preserved", purl: "pkg:npm/%40Scope/Pkg@1.2.3", wantName: "@Scope/Pkg", wantVersion: "1.2.3", wantOK: true},
		{name: "prerelease version", purl: "pkg:npm/pkg@1.0.0-beta.1", wantName: "pkg", wantVersion: "1.0.0-beta.1", wantOK: true},
		{name: "qualifiers are ignored", purl: "pkg:npm/lodash@4.17.21?arch=x64", wantName: "lodash", wantVersion: "4.17.21", wantOK: true},
		{name: "subpath is ignored", purl: "pkg:npm/lodash@4.17.21#fp", wantName: "lodash", wantVersion: "4.17.21", wantOK: true},
		{name: "another ecosystem", purl: "pkg:pypi/requests@2.0.0", wantOK: false},
		{name: "no version", purl: "pkg:npm/lodash", wantOK: false},
		{name: "empty version", purl: "pkg:npm/lodash@", wantOK: false},
		{name: "empty name", purl: "pkg:npm/@1.0.0", wantOK: false},
		{name: "not a purl", purl: "lodash@4.17.21", wantOK: false},
		{name: "empty", purl: "", wantOK: false},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			name, version, ok := parseNPMPURL(test.purl)
			if ok != test.wantOK {
				t.Fatalf("parseNPMPURL(%q) ok = %v, want %v (name %q version %q)", test.purl, ok, test.wantOK, name, version)
			}
			if !test.wantOK {
				return
			}
			if name != test.wantName || version != test.wantVersion {
				t.Fatalf("parseNPMPURL(%q) = (%q, %q), want (%q, %q)", test.purl, name, version, test.wantName, test.wantVersion)
			}
		})
	}
}

func TestCorrelationExactComponent(t *testing.T) {
	t.Parallel()

	t.Run("unscoped package", func(t *testing.T) {
		t.Parallel()
		got := resolveWithSBOM(t, "lodash", docWith("pkg:npm/lodash@4.17.21"))
		if got.Status != jsresolution.StatusComponent {
			t.Fatalf("status = %q, want component (reason %q)", got.Status, got.Reason)
		}
		if got.Package.PURL != "pkg:npm/lodash@4.17.21" {
			t.Fatalf("purl = %q, want the exact component purl", got.Package.PURL)
		}
		if got.Package.Version != "4.17.21" {
			t.Fatalf("version = %q, want 4.17.21", got.Package.Version)
		}
	})

	t.Run("scoped package", func(t *testing.T) {
		t.Parallel()
		got := resolveWithSBOM(t, "@scope/pkg", docWith("pkg:npm/%40scope/pkg@1.2.3"))
		if got.Status != jsresolution.StatusComponent || got.Package.PURL != "pkg:npm/%40scope/pkg@1.2.3" {
			t.Fatalf("a scoped package must correlate to its exact purl, got %+v", got)
		}
	})

	t.Run("package subpath resolves to the package root", func(t *testing.T) {
		t.Parallel()
		got := resolveWithSBOM(t, "lodash/fp", docWith("pkg:npm/lodash@4.17.21"))
		if got.Status != jsresolution.StatusComponent || got.Package.PURL != "pkg:npm/lodash@4.17.21" {
			t.Fatalf("a subpath import must correlate to the package root, got %+v", got)
		}
	})

	t.Run("scoped package subpath", func(t *testing.T) {
		t.Parallel()
		got := resolveWithSBOM(t, "@scope/pkg/deep/path", docWith("pkg:npm/%40scope/pkg@1.2.3"))
		if got.Status != jsresolution.StatusComponent {
			t.Fatalf("a scoped subpath must correlate to the package root, got %+v", got)
		}
	})

	t.Run("other components are ignored", func(t *testing.T) {
		t.Parallel()
		doc := docWith("pkg:pypi/lodash@1.0.0", "pkg:golang/lodash@1.0.0", "pkg:npm/lodash@4.17.21")
		got := resolveWithSBOM(t, "lodash", doc)
		if got.Status != jsresolution.StatusComponent || got.Package.PURL != "pkg:npm/lodash@4.17.21" {
			t.Fatalf("only the npm component may correlate, got %+v", got)
		}
	})
}

// TestCorrelationNeverGuesses is the safety gate for #400: a package that cannot be identified
// deterministically must stay explicit, and every non-deterministic outcome must degrade coverage so no
// later analyzer can draw a negative conclusion from it.
func TestCorrelationNeverGuesses(t *testing.T) {
	t.Parallel()

	t.Run("multiple versions stay ambiguous with every candidate", func(t *testing.T) {
		t.Parallel()
		doc := docWith("pkg:npm/lodash@4.17.21", "pkg:npm/lodash@3.10.1")
		got := resolveWithSBOM(t, "lodash", doc)
		if got.Status != jsresolution.StatusAmbiguous {
			t.Fatalf("two versions must be ambiguous, got %q", got.Status)
		}
		if len(got.Candidates) != 2 {
			t.Fatalf("both versions must be preserved, got %+v", got.Candidates)
		}
		if got.Package != (jsresolution.PackageIdentity{}) {
			t.Fatalf("an ambiguous resolution must select no package, got %+v", got.Package)
		}
		// The candidate order must be deterministic, never slice or map order.
		if got.Candidates[0].Version != "3.10.1" || got.Candidates[1].Version != "4.17.21" {
			t.Fatalf("candidates must be deterministically ordered, got %+v", got.Candidates)
		}
	})

	t.Run("absent component stays unresolved", func(t *testing.T) {
		t.Parallel()
		got := resolveWithSBOM(t, "never-installed", docWith("pkg:npm/lodash@4.17.21"))
		if got.Status != jsresolution.StatusUnresolved {
			t.Fatalf("an absent component must stay unresolved, got %q", got.Status)
		}
		if got.Reason == "" {
			t.Fatal("an unresolved package must carry a reason")
		}
	})

	t.Run("no sbom cannot correlate", func(t *testing.T) {
		t.Parallel()
		got := resolveWithSBOM(t, "lodash", nil)
		if got.Status != jsresolution.StatusUnresolved {
			t.Fatalf("without an sbom nothing may be correlated, got %q", got.Status)
		}
	})

	t.Run("unresolved component version is never an identity", func(t *testing.T) {
		t.Parallel()
		// A floating version is not a resolved subject, so it must not become an exact identity.
		got := resolveWithSBOM(t, "lodash", docWith("pkg:npm/lodash@latest"))
		if got.Status == jsresolution.StatusComponent {
			t.Fatalf("a floating version must never become an exact component identity, got %+v", got)
		}
	})
}

func TestCorrelationDegradesCoverage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		specifier string
		doc       *sbom.SBOM
		wantKind  jsresolution.CoverageIssueKind
	}{
		{
			name:      "missing component",
			specifier: "absent-pkg",
			doc:       docWith("pkg:npm/lodash@4.17.21"),
			wantKind:  jsresolution.CoverageMissingSBOMComponent,
		},
		{
			name:      "ambiguous component",
			specifier: "lodash",
			doc:       docWith("pkg:npm/lodash@4.17.21", "pkg:npm/lodash@3.10.1"),
			wantKind:  jsresolution.CoverageAmbiguousSBOMComponent,
		},
		{
			name:      "no sbom supplied",
			specifier: "lodash",
			doc:       nil,
			wantKind:  jsresolution.CoverageMissingSBOMComponent,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "app", "version": "1.0.0"})
			graph := graphWithExternal("src/index.ts", test.specifier)

			result, err := NewResolver().Resolve(context.Background(), root, graph, test.doc)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if !hasCoverageKind(result.Coverage, test.wantKind) {
				t.Fatalf("expected coverage kind %q, got %+v", test.wantKind, result.Coverage)
			}
			// Any non-deterministic identity must leave the result incomplete, which is what stops a
			// later analyzer from concluding a dependency is unreachable.
			if result.Complete {
				t.Fatal("a non-deterministic correlation must leave the result incomplete")
			}
		})
	}
}

// TestCorrelationCompletesACleanProject proves the converse: when every import correlates
// deterministically the result is Complete, which is the precondition for any negative proof.
func TestCorrelationCompletesACleanProject(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "app", "version": "1.0.0"})
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{{Path: "src/index.ts", Dialect: modulegraph.DialectTypeScript}},
		Edges: []modulegraph.Edge{
			{From: "src/index.ts", Specifier: "lodash", Kind: modulegraph.ImportESMStatic},
			{From: "src/index.ts", Specifier: "node:fs", Kind: modulegraph.ImportESMStatic},
			{From: "src/index.ts", Specifier: "@scope/pkg", Kind: modulegraph.ImportESMStatic},
		},
	}
	doc := docWith("pkg:npm/lodash@4.17.21", "pkg:npm/%40scope/pkg@1.2.3")

	result, err := NewResolver().Resolve(context.Background(), root, graph, doc)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !result.Complete {
		t.Fatalf("a fully correlated project must be complete, coverage %+v imports %+v", result.Coverage, result.Imports)
	}
	byName := resolutionsBySpecifier(result.Imports)
	if byName["lodash"].Status != jsresolution.StatusComponent {
		t.Errorf("lodash status = %q", byName["lodash"].Status)
	}
	if byName["node:fs"].Status != jsresolution.StatusBuiltin {
		t.Errorf("node:fs must stay a builtin, got %q", byName["node:fs"].Status)
	}
	if byName["@scope/pkg"].Status != jsresolution.StatusComponent {
		t.Errorf("@scope/pkg status = %q", byName["@scope/pkg"].Status)
	}
}

// TestWorkspaceIsNeverAThirdPartyComponent locks the #400 criterion that a first-party workspace package
// is never misclassified as a third-party component, even when the SBOM contains a same-named package.
func TestWorkspaceIsNeverAThirdPartyComponent(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "private": true, "workspaces": []string{"packages/*"}})
	writeJSON(t, r2bJoin(root, "packages", "shared", "package.json"), map[string]any{"name": "@repo/shared", "version": "1.2.3"})
	graph := graphWithExternal("src/index.ts", "@repo/shared")

	t.Run("with a same-named registry component", func(t *testing.T) {
		doc := docWith("pkg:npm/%40repo/shared@9.9.9")
		result, err := NewResolver().Resolve(context.Background(), root, graph, doc)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		got := resolutionsBySpecifier(result.Imports)["@repo/shared"]
		if got.Status == jsresolution.StatusComponent {
			t.Fatalf("a local workspace must never resolve to a third-party component, got %+v", got)
		}
		if got.Status != jsresolution.StatusAmbiguous {
			t.Fatalf("status = %q, want ambiguous", got.Status)
		}
		// Both the workspace and the concrete registry identity must be preserved.
		var sawWorkspace, sawRegistry bool
		for _, candidate := range got.Candidates {
			if candidate.Workspace {
				sawWorkspace = true
			}
			if candidate.PURL == "pkg:npm/%40repo/shared@9.9.9" {
				sawRegistry = true
			}
		}
		if !sawWorkspace || !sawRegistry {
			t.Fatalf("both identities must be preserved, got %+v", got.Candidates)
		}
	})

	t.Run("with no registry component", func(t *testing.T) {
		result, err := NewResolver().Resolve(context.Background(), root, graph, docWith("pkg:npm/lodash@4.17.21"))
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		got := resolutionsBySpecifier(result.Imports)["@repo/shared"]
		if got.Status == jsresolution.StatusComponent {
			t.Fatalf("a local workspace must never resolve to a third-party component, got %+v", got)
		}
	})
}

func TestCorrelationIsDeterministic(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "app", "version": "1.0.0"})
	graph := graphWithExternal("src/index.ts", "lodash")
	// Component order in the SBOM must not affect the outcome.
	forward := docWith("pkg:npm/lodash@4.17.21", "pkg:npm/lodash@3.10.1", "pkg:npm/lodash@2.4.2")
	reverse := docWith("pkg:npm/lodash@2.4.2", "pkg:npm/lodash@3.10.1", "pkg:npm/lodash@4.17.21")

	first, err := NewResolver().Resolve(context.Background(), root, graph, forward)
	if err != nil {
		t.Fatalf("resolve forward: %v", err)
	}
	second, err := NewResolver().Resolve(context.Background(), root, graph, reverse)
	if err != nil {
		t.Fatalf("resolve reverse: %v", err)
	}
	a := resolutionsBySpecifier(first.Imports)["lodash"]
	b := resolutionsBySpecifier(second.Imports)["lodash"]
	if len(a.Candidates) != len(b.Candidates) {
		t.Fatalf("candidate count differs: %d vs %d", len(a.Candidates), len(b.Candidates))
	}
	for i := range a.Candidates {
		if a.Candidates[i] != b.Candidates[i] {
			t.Fatalf("candidate[%d] differs between component orderings: %+v vs %+v", i, a.Candidates[i], b.Candidates[i])
		}
	}
}

func TestCorrelationHandlesDuplicateComponents(t *testing.T) {
	t.Parallel()

	// The same component listed twice is one identity, not an ambiguity.
	got := resolveWithSBOM(t, "lodash", docWith("pkg:npm/lodash@4.17.21", "pkg:npm/lodash@4.17.21"))
	if got.Status != jsresolution.StatusComponent {
		t.Fatalf("duplicate identical components must not create ambiguity, got %+v", got)
	}
}

func TestCorrelationRejectsMalformedComponentPURLs(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "app", "version": "1.0.0"})
	graph := graphWithExternal("src/index.ts", "lodash")
	// A malformed npm PURL must degrade coverage rather than be silently skipped: the component it
	// stands for may be the very package being imported.
	doc := docWith("pkg:npm/lodash", "pkg:npm/lodash@4.17.21")

	result, err := NewResolver().Resolve(context.Background(), root, graph, doc)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !hasCoverageKind(result.Coverage, jsresolution.CoverageMissingSBOMComponent) {
		t.Fatalf("an uninterpretable component purl must degrade coverage, got %+v", result.Coverage)
	}
}

func TestCorrelationMatchesAcrossCase(t *testing.T) {
	t.Parallel()

	// npm hosts DISTINCT packages whose names differ only in case (JSONStream and jsonstream are not the
	// same package). A specifier's package root is lowercased during normalization, so a component that
	// matches only after folding is plausible, not proven: it must be reported rather than sealed as a
	// deterministic identity, or one package's purl would be attached to another package's import.
	got := resolveWithSBOM(t, "@Scope/Pkg", docWith("pkg:npm/%40Scope/Pkg@1.2.3"))
	if got.Status == jsresolution.StatusComponent {
		t.Fatalf("a case-folded match must never be sealed as a deterministic component, got %+v", got)
	}
	if got.Reason == "" {
		t.Fatal("a case-folded match must explain itself")
	}
}

func TestCorrelationNeverFoldsDistinctPackages(t *testing.T) {
	t.Parallel()

	// The concrete hazard: JSONStream and jsonstream are different published packages. An import of one
	// must never be given the other's purl.
	got := resolveWithSBOM(t, "jsonstream", docWith("pkg:npm/JSONStream@1.3.5"))
	if got.Status == jsresolution.StatusComponent {
		t.Fatalf("an import of jsonstream must not be given JSONStream's identity, got %+v", got)
	}
}

func TestDeclaredDependencySpecDecidesIdentity(t *testing.T) {
	t.Parallel()

	// An npm ALIAS means the imported name is not the package name. Correlating "lodash" to a
	// same-named component here would attach the WRONG identity and leave the real package
	// (lodash-es) named by no import — exactly the false-negative this phase exists to prevent.
	t.Run("npm alias redirects to the real package", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
			"name": "app", "version": "1.0.0",
			"dependencies": map[string]string{"lodash": "npm:lodash-es@^4.17.21"},
		})
		graph := graphWithExternal("src/index.ts", "lodash")
		doc := docWith("pkg:npm/lodash-es@4.17.21", "pkg:npm/lodash@4.17.15")

		result, err := NewResolver().Resolve(context.Background(), root, graph, doc)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		got := resolutionsBySpecifier(result.Imports)["lodash"]
		if got.Status != jsresolution.StatusComponent {
			t.Fatalf("an aliased dependency must correlate to its real package, got %+v", got)
		}
		if got.Package.PURL != "pkg:npm/lodash-es@4.17.21" {
			t.Fatalf("purl = %q, want the ALIAS TARGET lodash-es, not the same-named component", got.Package.PURL)
		}
	})

	nonRegistry := map[string]string{
		"file":      "file:../local-copy",
		"link":      "link:../sibling",
		"workspace": "workspace:*",
		"git":       "git+ssh://git@github.com/o/r.git",
		"github":    "github:owner/repo",
		"https":     "https://example.com/pkg.tgz",
		"patch":     "patch:lodash@4.17.21#./fix.patch",
		"shorthand": "owner/repo",
	}
	for label, spec := range nonRegistry {
		label, spec := label, spec
		t.Run("non-registry source refuses correlation: "+label, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
				"name": "app", "version": "1.0.0",
				"dependencies": map[string]string{"lodash": spec},
			})
			graph := graphWithExternal("src/index.ts", "lodash")
			// A same-named registry component exists, and must NOT be adopted.
			doc := docWith("pkg:npm/lodash@4.17.21")

			result, err := NewResolver().Resolve(context.Background(), root, graph, doc)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			got := resolutionsBySpecifier(result.Imports)["lodash"]
			if got.Status == jsresolution.StatusComponent {
				t.Fatalf("a %s dependency must not adopt a same-named registry component, got %+v", label, got)
			}
			if result.Complete {
				t.Fatal("a non-registry dependency must leave the result incomplete")
			}
		})
	}

	t.Run("a plain range still correlates", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
			"name": "app", "version": "1.0.0",
			"dependencies": map[string]string{"lodash": "^4.17.21"},
		})
		graph := graphWithExternal("src/index.ts", "lodash")
		result, err := NewResolver().Resolve(context.Background(), root, graph, docWith("pkg:npm/lodash@4.17.21"))
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		got := resolutionsBySpecifier(result.Imports)["lodash"]
		if got.Status != jsresolution.StatusComponent {
			t.Fatalf("a plain semver range must correlate normally, got %+v", got)
		}
	})
}

func TestPackageImportsAliasCorrelates(t *testing.T) {
	t.Parallel()

	// A package.json "imports" target naming a third-party package must correlate exactly like a bare
	// import; leaving it unresolved would make any project using the feature permanently incomplete.
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name": "app", "version": "1.0.0",
		"imports": map[string]any{"#dep": "lodash"},
	})
	graph := graphWithExternal("src/index.ts", "#dep")

	result, err := NewResolver().Resolve(context.Background(), root, graph, docWith("pkg:npm/lodash@4.17.21"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := resolutionsBySpecifier(result.Imports)["#dep"]
	if got.Status != jsresolution.StatusComponent {
		t.Fatalf("an imports target naming a package must correlate, got %+v", got)
	}
	if got.Package.PURL != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("purl = %q, want the correlated component", got.Package.PURL)
	}
}

func TestWorkspaceOnlyIdentityWithACompleteSBOM(t *testing.T) {
	t.Parallel()

	// A COMPLETE sbom that lists no package of this name is positive evidence that no registry package
	// was installed, so the workspace is the only identity. Keeping a bare-name alternative would leave
	// every monorepo import permanently ambiguous and block all later negative conclusions.
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "private": true, "workspaces": []string{"packages/*"}})
	writeJSON(t, r2bJoin(root, "packages", "shared", "package.json"), map[string]any{"name": "@repo/shared", "version": "1.2.3"})
	graph := graphWithExternal("src/index.ts", "@repo/shared")

	result, err := NewResolver().Resolve(context.Background(), root, graph, docWith("pkg:npm/lodash@4.17.21"))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := resolutionsBySpecifier(result.Imports)["@repo/shared"]
	if got.Status != jsresolution.StatusWorkspace {
		t.Fatalf("status = %q, want workspace (reason %q candidates %+v)", got.Status, got.Reason, got.Candidates)
	}
	if !got.Package.Workspace || got.Package.Path == "" {
		t.Fatalf("the workspace identity must carry its path, got %+v", got.Package)
	}
	if !result.Complete {
		t.Fatalf("a monorepo whose imports all resolve must be complete, coverage %+v", result.Coverage)
	}
}

func TestComponentBudgetDegradesRatherThanTruncatesSilently(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "app", "version": "1.0.0"})
	graph := graphWithExternal("src/index.ts", "lodash")

	limits := defaultResolverLimits()
	limits.maxComponents = 1
	resolver := newResolverWithLimits(NewInventoryBuilder(), newAliasInventoryBuilder(), limits)
	// lodash is past the cut, so it must NOT look absent from the sbom.
	doc := docWith("pkg:npm/other@1.0.0", "pkg:npm/lodash@4.17.21")

	result, err := resolver.Resolve(context.Background(), root, graph, doc)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !hasCoverageKind(result.Coverage, jsresolution.CoverageMetadataBudgetExceeded) {
		t.Fatalf("a truncated sbom must degrade coverage, got %+v", result.Coverage)
	}
	if result.Complete {
		t.Fatal("a truncated sbom must leave the result incomplete")
	}
}

func TestPerNameCandidateBudgetIsReported(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "app", "version": "1.0.0"})
	graph := graphWithExternal("src/index.ts", "lodash")

	limits := defaultResolverLimits()
	limits.maxCandidates = 2
	resolver := newResolverWithLimits(NewInventoryBuilder(), newAliasInventoryBuilder(), limits)
	doc := docWith("pkg:npm/lodash@1.0.0", "pkg:npm/lodash@2.0.0", "pkg:npm/lodash@3.0.0")

	result, err := resolver.Resolve(context.Background(), root, graph, doc)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := resolutionsBySpecifier(result.Imports)["lodash"]
	if got.Status == jsresolution.StatusComponent {
		t.Fatalf("an over-budget name must not produce a deterministic identity, got %+v", got)
	}
	// The reason must not claim the package is absent when the sbom lists many versions of it.
	if got.Reason == "package is imported by first-party source but is absent from the sbom" {
		t.Fatalf("an over-budget name must not be reported as absent from the sbom: %q", got.Reason)
	}
	if result.Complete {
		t.Fatal("an over-budget name must leave the result incomplete")
	}
}
