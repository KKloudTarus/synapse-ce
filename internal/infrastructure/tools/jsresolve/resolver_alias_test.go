package jsresolve

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestResolverDeterministicAcrossRepeatedRuns(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "workspaces": []string{"packages/*"}})
	writeJSON(t, r2bJoin(root, "packages", "shared", "package.json"), map[string]any{"name": "@repo/shared"})
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{{Path: "src/index.ts", Dialect: modulegraph.DialectTypeScript}},
		Edges: []modulegraph.Edge{
			{From: "src/index.ts", Specifier: "lodash/fp", Kind: modulegraph.ImportESMStatic},
			{From: "src/index.ts", Specifier: "@repo/shared", Kind: modulegraph.ImportCommonJS},
			{From: "src/index.ts", Specifier: "node:fs", Kind: modulegraph.ImportESMStatic},
		},
	}
	resolver := NewResolver()
	first, err := resolver.Resolve(context.Background(), root, graph, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		got, err := resolver.Resolve(context.Background(), root, graph, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(first, got) {
			t.Fatalf("run %d differs\nfirst=%#v\ngot=%#v", i, first, got)
		}
	}
}

func TestResolverHardFailuresForInvalidGraphAndCancellation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	resolver := NewResolver()
	if _, err := resolver.Resolve(context.Background(), root, modulegraph.Graph{}, nil); err == nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty graph error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.Resolve(ctx, root, graphWithExternal("src/index.ts", "fs"), nil); err != context.Canceled {
		t.Fatalf("canceled resolver error = %v", err)
	}
}

func TestResolverTSPathsCanResolveNonNPMAliasSyntax(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	writeFile(t, r2bJoin(root, "tsconfig.json"), `{"compilerOptions":{"moduleResolution":"bundler","paths":{"@/*":["src/*"]}}}`)
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{
			{Path: "src/index.ts", Dialect: modulegraph.DialectTypeScript},
			{Path: "src/utils.ts", Dialect: modulegraph.DialectTypeScript},
		},
		Edges: []modulegraph.Edge{{From: "src/index.ts", Specifier: "@/utils", Kind: modulegraph.ImportESMStatic}},
	}
	got, err := NewResolver().Resolve(context.Background(), root, graph, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusLocal || got.Imports[0].Package.Path != "." || !got.Complete {
		t.Fatalf("non-npm tsconfig alias resolution = %#v", got)
	}
}

func TestResolverTSPathsMissingTargetCannotMasqueradeAsLocal(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	writeFile(t, r2bJoin(root, "tsconfig.json"), `{"compilerOptions":{"moduleResolution":"bundler","paths":{"*":["src/*"]}}}`)
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), nil)
	if err != nil {
		t.Fatal(err)
	}
	resolution := got.Imports[0]
	if resolution.Status != jsresolution.StatusUnresolved || resolution.Package.Name != "" || !hasCoverageKind(got.Coverage, jsresolution.CoverageUnresolvedAlias) {
		t.Fatalf("missing paths target was treated as local/package evidence: resolution=%#v coverage=%#v", resolution, got.Coverage)
	}
}

func TestResolverBaseURLPreventsUnsafeBarePackageClassification(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	writeFile(t, r2bJoin(root, "tsconfig.json"), `{"compilerOptions":{"baseUrl":"src"}}`)
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "lodash"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusUnresolved || got.Imports[0].Package.Name != "" || !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedAlias) {
		t.Fatalf("baseUrl bare package classification was not conservative: %#v", got)
	}
}

func TestResolverMultipleTSConfigContextsDoNotGuess(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "workspaces": []string{"packages/*"}})
	writeJSON(t, r2bJoin(root, "packages", "app", "package.json"), map[string]any{"name": "app"})
	writeFile(t, r2bJoin(root, "tsconfig.json"), `{"compilerOptions":{"moduleResolution":"bundler","paths":{"@x/*":["src/*"]}}}`)
	writeFile(t, r2bJoin(root, "packages", "app", "tsconfig.json"), `{"compilerOptions":{}}`)
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{
			{Path: "packages/app/src/index.ts", Dialect: modulegraph.DialectTypeScript},
			{Path: "src/value.ts", Dialect: modulegraph.DialectTypeScript},
		},
		Edges: []modulegraph.Edge{{From: "packages/app/src/index.ts", Specifier: "@x/value", Kind: modulegraph.ImportESMStatic}},
	}
	got, err := NewResolver().Resolve(context.Background(), root, graph, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusUnresolved || !hasCoverageKind(got.Coverage, jsresolution.CoverageUnresolvedAlias) {
		t.Fatalf("multiple tsconfig contexts were guessed: %#v", got)
	}
}

func TestResolverTSConfigProjectSelectionDoesNotGuessAliasApplicability(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	writeFile(t, r2bJoin(root, "tsconfig.json"), `{"include":["src/special/**"],"compilerOptions":{"moduleResolution":"bundler","paths":{"@x/*":["src/*"]}}}`)
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{
			{Path: "src/index.ts", Dialect: modulegraph.DialectTypeScript},
			{Path: "src/value.ts", Dialect: modulegraph.DialectTypeScript},
		},
		Edges: []modulegraph.Edge{{From: "src/index.ts", Specifier: "@x/value", Kind: modulegraph.ImportESMStatic}},
	}
	got, err := NewResolver().Resolve(context.Background(), root, graph, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusUnresolved || !hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedAlias) {
		t.Fatalf("explicit project selection was guessed: %#v", got)
	}
}

func TestResolverPackageImportsPreservesWorkspaceAndRegistryAmbiguity(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name": "root", "workspaces": []string{"packages/*"}, "imports": map[string]any{"#dup": "dup"},
	})
	writeJSON(t, r2bJoin(root, "packages", "a", "package.json"), map[string]any{"name": "dup"})
	writeJSON(t, r2bJoin(root, "packages", "b", "package.json"), map[string]any{"name": "dup"})
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "#dup"), nil)
	if err != nil {
		t.Fatal(err)
	}
	resolution := got.Imports[0]
	if resolution.Status != jsresolution.StatusAmbiguous || len(resolution.Candidates) != 3 || !hasWorkspaceCandidate(resolution.Candidates, "dup", "packages/a") || !hasWorkspaceCandidate(resolution.Candidates, "dup", "packages/b") {
		t.Fatalf("workspace/registry ambiguity was collapsed: %#v", resolution)
	}
	external := false
	for _, candidate := range resolution.Candidates {
		if candidate.Name == "dup" && !candidate.Workspace && candidate.Path == "" && candidate.Version == "" && candidate.PURL == "" {
			external = true
		}
	}
	if !external {
		t.Fatalf("external package candidate was lost: %#v", resolution.Candidates)
	}
}
