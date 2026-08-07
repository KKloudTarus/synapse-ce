package jsresolve

import (
	"context"
	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
	"testing"
)

func TestResolverUnsupportedExactPackageImportCannotFallThroughToWildcard(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, r2bJoin(root, "package.json"), `{
  "name":"root",
  "imports":{
    "#x":{"default":"lodash"},
    "#*":"left-pad"
  }
}`)
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "#x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	resolution := got.Imports[0]
	if resolution.Status != jsresolution.StatusUnresolved || resolution.Package.Name != "" {
		t.Fatalf("unsupported exact imports entry fell through to wildcard: %#v", resolution)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedAlias) {
		t.Fatalf("missing unsupported alias coverage: %#v", got.Coverage)
	}
}

func TestResolverMalformedNestedPackageBoundaryPreventsParentImportsLeak(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, r2bJoin(root, "package.json"), `{"name":"root","imports":{"#x":"lodash"}}`)
	writeFile(t, r2bJoin(root, "packages", "app", "package.json"), `{not-json`)

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("packages/app/src/index.ts", "#x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	resolution := got.Imports[0]
	if resolution.Status != jsresolution.StatusUnresolved || resolution.Package.Name != "" {
		t.Fatalf("parent imports mapping leaked through malformed nested package boundary: %#v", resolution)
	}
	if got.Complete || !hasCoverageKind(got.Coverage, jsresolution.CoverageMalformedMetadata) {
		t.Fatalf("malformed nested package did not keep resolution incomplete: %#v", got)
	}
}

func TestResolverPartialTSPathsConfigCannotProduceCertainAliasIdentity(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	writeFile(t, r2bJoin(root, "tsconfig.json"), `{
  "compilerOptions":{"moduleResolution":"bundler","paths":{"@ok/*":["src/*"],"@bad/*":["node_modules/pkg/*"]}}
}`)
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{
			{Path: "src/index.ts", Dialect: modulegraph.DialectTypeScript},
			{Path: "src/value.ts", Dialect: modulegraph.DialectTypeScript},
		},
		Edges: []modulegraph.Edge{{From: "src/index.ts", Specifier: "@ok/value", Kind: modulegraph.ImportESMStatic}},
	}
	got, err := NewResolver().Resolve(context.Background(), root, graph, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusUnresolved || got.Complete {
		t.Fatalf("partial tsconfig paths produced a certain identity: %#v", got)
	}
}

func TestResolverWorkspaceSelfReferenceRequiresExportsSemantics(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "private": true})
	writeFile(t, r2bJoin(root, "pnpm-workspace.yaml"), "packages:\n  - 'packages/*'\n")

	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "root"), nil)
	if err != nil {
		t.Fatal(err)
	}
	resolution := got.Imports[0]
	if resolution.Status != jsresolution.StatusUnresolved || resolution.Package.Name != "root" || !hasCoverageKind(got.Coverage, jsresolution.CoverageUnresolvedSpecifier) {
		t.Fatalf("workspace self-reference bypassed exports uncertainty: resolution=%#v coverage=%#v", resolution, got.Coverage)
	}
}

func TestResolverTSConfigPathsFallsBackAfterMissingFirstTarget(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "workspaces": []string{"packages/*"}})
	writeJSON(t, r2bJoin(root, "packages", "b", "package.json"), map[string]any{"name": "b"})
	writeFile(t, r2bJoin(root, "tsconfig.json"), `{"compilerOptions":{"moduleResolution":"bundler","paths":{"@alias/*":["missing/*","packages/b/*"]}}}`)
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{
			{Path: "src/index.ts", Dialect: modulegraph.DialectTypeScript},
			{Path: "packages/b/value.ts", Dialect: modulegraph.DialectTypeScript},
		},
		Edges: []modulegraph.Edge{{From: "src/index.ts", Specifier: "@alias/value", Kind: modulegraph.ImportESMStatic}},
	}
	got, err := NewResolver().Resolve(context.Background(), root, graph, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusWorkspace || got.Imports[0].Package.Path != "packages/b" || !got.Complete {
		t.Fatalf("paths fallback after missing first target = %#v", got)
	}
}

func TestResolverTSConfigUnknownResolutionModeDoesNotAssumeExtensionlessLookup(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	writeFile(t, r2bJoin(root, "tsconfig.json"), `{"compilerOptions":{"paths":{"@app/*":["src/*"]}}}`)
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{
			{Path: "src/index.ts", Dialect: modulegraph.DialectTypeScript},
			{Path: "src/value.ts", Dialect: modulegraph.DialectTypeScript},
		},
		Edges: []modulegraph.Edge{{From: "src/index.ts", Specifier: "@app/value", Kind: modulegraph.ImportESMStatic}},
	}
	got, err := NewResolver().Resolve(context.Background(), root, graph, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusUnresolved || !hasCoverageKind(got.Coverage, jsresolution.CoverageUnresolvedAlias) {
		t.Fatalf("unknown moduleResolution guessed extensionless lookup: %#v", got)
	}
}

func TestResolverTSConfigStrictNodeAllowsExplicitJSExtensionSubstitution(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	writeFile(t, r2bJoin(root, "tsconfig.json"), `{"compilerOptions":{"moduleResolution":"nodenext","paths":{"@app":["src/value.js"]}}}`)
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{
			{Path: "src/index.ts", Dialect: modulegraph.DialectTypeScript},
			{Path: "src/value.ts", Dialect: modulegraph.DialectTypeScript},
		},
		Edges: []modulegraph.Edge{{From: "src/index.ts", Specifier: "@app", Kind: modulegraph.ImportESMStatic}},
	}
	got, err := NewResolver().Resolve(context.Background(), root, graph, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusLocal || got.Imports[0].Package.Path != "." || !got.Complete {
		t.Fatalf("explicit .js extension substitution was not recognized conservatively: %#v", got)
	}
}
