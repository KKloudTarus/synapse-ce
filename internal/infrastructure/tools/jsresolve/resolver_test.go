package jsresolve

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
)

func TestResolverClassifiesBuiltinsWorkspaceCandidatesPackagesAndPreservesEdgeSemantics(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":       "root-app",
		"private":    true,
		"workspaces": []string{"packages/*"},
	})
	writeJSON(t, r2bJoin(root, "packages", "shared", "package.json"), map[string]any{"name": "@repo/shared", "version": "1.2.3"})

	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{
			{Path: "src/index.ts", Dialect: modulegraph.DialectTypeScript},
			{Path: "types/api.d.ts", Dialect: modulegraph.DialectTypeScript, DeclarationOnly: true},
			{Path: "src/local.ts", Dialect: modulegraph.DialectTypeScript},
		},
		Edges: []modulegraph.Edge{
			{From: "src/index.ts", Specifier: "fs/promises", Kind: modulegraph.ImportCommonJS, Position: modulegraph.Position{Line: 1, Column: 1}},
			{From: "src/index.ts", Specifier: "lodash/fp", Kind: modulegraph.ImportESMStatic, Position: modulegraph.Position{Line: 2, Column: 1}},
			{From: "src/index.ts", Specifier: "@repo/shared/subpath", Kind: modulegraph.ImportESMDynamic, Position: modulegraph.Position{Line: 3, Column: 1}},
			{From: "types/api.d.ts", Specifier: "@repo/shared", Kind: modulegraph.ImportESMStatic, TypeOnly: true, Position: modulegraph.Position{Line: 1, Column: 1}},
			{From: "src/index.ts", To: "src/local.ts", Specifier: "./local", Kind: modulegraph.ImportESMStatic},
		},
		Coverage: []modulegraph.CoverageIssue{{Kind: modulegraph.CoverageDynamicImport, Path: "src/index.ts", Line: 9, Detail: "dynamic import"}},
	}

	got, err := NewResolver().Resolve(context.Background(), root, graph, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Imports) != 4 {
		t.Fatalf("imports = %#v", got.Imports)
	}
	bySpecifier := resolutionsBySpecifier(got.Imports)
	if fs := bySpecifier["fs/promises"]; fs.Status != jsresolution.StatusBuiltin || fs.Package.Name != "node:fs/promises" {
		t.Fatalf("builtin resolution = %#v", fs)
	}
	if lodash := bySpecifier["lodash/fp"]; lodash.Status != jsresolution.StatusUnresolved || lodash.Package.Name != "lodash" {
		t.Fatalf("third-party package root = %#v", lodash)
	}
	if shared := bySpecifier["@repo/shared/subpath"]; shared.Status != jsresolution.StatusAmbiguous || !hasWorkspaceCandidate(shared.Candidates, "@repo/shared", "packages/shared") || shared.Kind != modulegraph.ImportESMDynamic {
		t.Fatalf("workspace/external ambiguity = %#v", shared)
	}
	if decl := bySpecifier["@repo/shared"]; decl.Status != jsresolution.StatusAmbiguous || !decl.TypeOnly || !decl.DeclarationOnly || !hasWorkspaceCandidate(decl.Candidates, "@repo/shared", "packages/shared") {
		t.Fatalf("declaration/type-only semantics = %#v", decl)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnresolvedSpecifier) {
		t.Fatalf("missing workspace/importer ambiguity coverage: %#v", got.Coverage)
	}
	if len(got.GraphCoverage) != 1 || got.GraphCoverage[0].Kind != modulegraph.CoverageDynamicImport {
		t.Fatalf("graph coverage not preserved: %#v", got.GraphCoverage)
	}
	if got.Complete {
		t.Fatal("R2B result with uncorrelated package identities reported complete")
	}
}

func TestResolverPackageImportsUsesNearestPackageScope(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name": "root", "imports": map[string]any{"#root": "lodash"},
	})
	writeJSON(t, r2bJoin(root, "packages", "app", "package.json"), map[string]any{"name": "app"})

	graph := graphWithExternal("packages/app/src/index.ts", "#root")
	got, err := NewResolver().Resolve(context.Background(), root, graph, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Imports) != 1 || got.Imports[0].Status != jsresolution.StatusUnresolved || got.Imports[0].Package.Name != "" {
		t.Fatalf("ancestor package imports mapping leaked across package scope: %#v", got.Imports)
	}
	if !hasCoverageKind(got.Coverage, jsresolution.CoverageUnresolvedAlias) {
		t.Fatalf("missing unresolved alias coverage: %#v", got.Coverage)
	}
}

func TestResolverPackageImportsCanResolveWorkspacePathAndExternalPackage(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":       "root",
		"workspaces": []string{"packages/*"},
		"imports": map[string]any{
			"#shared/*": "./packages/shared/src/*",
			"#dep":      "lodash/fp",
		},
	})
	writeJSON(t, r2bJoin(root, "packages", "shared", "package.json"), map[string]any{"name": "@repo/shared"})
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{{Path: "src/index.ts", Dialect: modulegraph.DialectTypeScript}},
		Edges: []modulegraph.Edge{
			{From: "src/index.ts", Specifier: "#shared/util", Kind: modulegraph.ImportESMStatic},
			{From: "src/index.ts", Specifier: "#dep", Kind: modulegraph.ImportESMStatic},
		},
	}
	got, err := NewResolver().Resolve(context.Background(), root, graph, nil)
	if err != nil {
		t.Fatal(err)
	}
	bySpecifier := resolutionsBySpecifier(got.Imports)
	if shared := bySpecifier["#shared/util"]; shared.Status != jsresolution.StatusWorkspace || shared.Package.Name != "@repo/shared" {
		t.Fatalf("package imports workspace resolution = %#v", shared)
	}
	if dep := bySpecifier["#dep"]; dep.Status != jsresolution.StatusUnresolved || dep.Package.Name != "lodash" {
		t.Fatalf("package imports external resolution = %#v", dep)
	}
}

func TestResolverTSConfigPathsSupportsJSONCWorkspaceAndLocalAliases(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name": "root", "private": true, "workspaces": []string{"packages/*"},
	})
	writeJSON(t, r2bJoin(root, "packages", "shared", "package.json"), map[string]any{"name": "@repo/shared"})
	writeFile(t, r2bJoin(root, "tsconfig.json"), `{
  // ordinary JSONC is supported without executing tsc
  "compilerOptions": {
    "moduleResolution": "bundler",
    "baseUrl": ".",
    "paths": {
      "@shared/*": ["packages/shared/src/*",],
      "@app/*": ["src/*"],
    },
  },
}`)
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{
			{Path: "src/index.ts", Dialect: modulegraph.DialectTypeScript},
			{Path: "src/config.ts", Dialect: modulegraph.DialectTypeScript},
			{Path: "packages/shared/src/logger.ts", Dialect: modulegraph.DialectTypeScript},
		},
		Edges: []modulegraph.Edge{
			{From: "src/index.ts", Specifier: "@shared/logger", Kind: modulegraph.ImportESMStatic},
			{From: "src/index.ts", Specifier: "@app/config", Kind: modulegraph.ImportESMStatic},
		},
	}
	got, err := NewResolver().Resolve(context.Background(), root, graph, nil)
	if err != nil {
		t.Fatal(err)
	}
	bySpecifier := resolutionsBySpecifier(got.Imports)
	if shared := bySpecifier["@shared/logger"]; shared.Status != jsresolution.StatusWorkspace || shared.Package.Path != "packages/shared" {
		t.Fatalf("tsconfig workspace alias = %#v", shared)
	}
	if local := bySpecifier["@app/config"]; local.Status != jsresolution.StatusLocal || local.Package.Path != "." || local.Package.Workspace {
		t.Fatalf("tsconfig local alias = %#v", local)
	}
	if !got.Complete {
		t.Fatalf("fully local/builtin alias resolution unexpectedly incomplete: coverage=%#v imports=%#v", got.Coverage, got.Imports)
	}
}

func TestResolverTSConfigPathsUsesFirstSuccessfulFallback(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "workspaces": []string{"packages/*"}})
	writeJSON(t, r2bJoin(root, "packages", "a", "package.json"), map[string]any{"name": "a"})
	writeJSON(t, r2bJoin(root, "packages", "b", "package.json"), map[string]any{"name": "b"})
	writeFile(t, r2bJoin(root, "tsconfig.json"), `{"compilerOptions":{"moduleResolution":"bundler","paths":{"@alias/*":["packages/a/*","packages/b/*"]}}}`)
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{
			{Path: "src/index.ts", Dialect: modulegraph.DialectTypeScript},
			{Path: "packages/a/value.ts", Dialect: modulegraph.DialectTypeScript},
			{Path: "packages/b/value.ts", Dialect: modulegraph.DialectTypeScript},
		},
		Edges: []modulegraph.Edge{{From: "src/index.ts", Specifier: "@alias/value", Kind: modulegraph.ImportESMStatic}},
	}
	got, err := NewResolver().Resolve(context.Background(), root, graph, nil)
	if err != nil {
		t.Fatal(err)
	}
	resolution := got.Imports[0]
	if resolution.Status != jsresolution.StatusWorkspace || resolution.Package.Path != "packages/a" || len(resolution.Candidates) != 0 {
		t.Fatalf("paths fallback did not stop at the first successful target: %#v coverage=%#v", resolution, got.Coverage)
	}
}

func TestResolverUnsupportedConditionalImportsCannotLookComplete(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, r2bJoin(root, "package.json"), `{"name":"root","imports":{"#x":{"node":"./x.js","default":"./y.js"}}}`)
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "#x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Complete || got.Imports[0].Status != jsresolution.StatusUnresolved || !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedAlias) {
		t.Fatalf("unsupported conditional mapping looked complete: %#v", got)
	}
}

func hasWorkspaceCandidate(values []jsresolution.PackageIdentity, name, path string) bool {
	for _, candidate := range values {
		if candidate.Name == name && candidate.Path == path && candidate.Workspace {
			return true
		}
	}
	return false
}
