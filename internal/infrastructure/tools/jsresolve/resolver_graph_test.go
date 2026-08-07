package jsresolve

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestResolverRelativeEdgeRequiresGraphCoverage(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{{Path: "src/index.ts", Dialect: modulegraph.DialectTypeScript}},
		Edges:   []modulegraph.Edge{{From: "src/index.ts", Specifier: "./missing", Kind: modulegraph.ImportESMStatic}},
	}
	if _, err := NewResolver().Resolve(context.Background(), root, graph, nil); err == nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("uncovered unresolved relative edge error = %v", err)
	}
	graph.Coverage = []modulegraph.CoverageIssue{{Kind: modulegraph.CoverageUnresolvedRelativeImport, Path: "src/index.ts", Detail: "missing"}}
	got, err := NewResolver().Resolve(context.Background(), root, graph, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Imports) != 0 || len(got.GraphCoverage) != 1 {
		t.Fatalf("covered unresolved relative edge handling = %#v", got)
	}
}

func TestResolverRelativeCoverageMustMatchSourceLineWhenAvailable(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	graph := modulegraph.Graph{
		Modules:  []modulegraph.Module{{Path: "src/index.ts", Dialect: modulegraph.DialectTypeScript}},
		Edges:    []modulegraph.Edge{{From: "src/index.ts", Specifier: "./missing", Kind: modulegraph.ImportESMStatic, Position: modulegraph.Position{Line: 9, Column: 1}}},
		Coverage: []modulegraph.CoverageIssue{{Kind: modulegraph.CoverageUnresolvedRelativeImport, Path: "src/index.ts", Line: 8, Detail: "different import"}},
	}
	if _, err := NewResolver().Resolve(context.Background(), root, graph, nil); err == nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("mismatched relative coverage line error = %v", err)
	}
}

func TestResolverRejectsResolvedNonRelativeGraphEdge(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{
			{Path: "src/index.ts", Dialect: modulegraph.DialectTypeScript},
			{Path: "src/local.ts", Dialect: modulegraph.DialectTypeScript},
		},
		Edges: []modulegraph.Edge{{From: "src/index.ts", To: "src/local.ts", Specifier: "lodash", Kind: modulegraph.ImportESMStatic}},
	}
	if _, err := NewResolver().Resolve(context.Background(), root, graph, nil); err == nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("resolved non-relative edge error = %v", err)
	}
}

func TestResolverLimitsAreInjectable(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	limits := defaultResolverLimits()
	limits.maxEdges = 1
	resolver := newResolverWithLimits(NewInventoryBuilder(), newAliasInventoryBuilder(), limits)
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{{Path: "src/index.ts", Dialect: modulegraph.DialectTypeScript}},
		Edges: []modulegraph.Edge{
			{From: "src/index.ts", Specifier: "fs", Kind: modulegraph.ImportESMStatic},
			{From: "src/index.ts", Specifier: "path", Kind: modulegraph.ImportESMStatic},
		},
	}
	if _, err := resolver.Resolve(context.Background(), root, graph, nil); err == nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("resolver edge budget error = %v", err)
	}
}

func TestResolverRejectsAggregateBindingProduct(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	limits := defaultResolverLimits()
	limits.maxTotalBindings = 1
	resolver := newResolverWithLimits(NewInventoryBuilder(), newAliasInventoryBuilder(), limits)
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{{Path: "src/index.ts", Dialect: modulegraph.DialectTypeScript}},
		Edges: []modulegraph.Edge{{
			From: "src/index.ts", Specifier: "lodash", Kind: modulegraph.ImportESMStatic,
			Bindings: []modulegraph.Binding{{Imported: "a", Local: "a"}, {Imported: "b", Local: "b"}},
		}},
	}
	if _, err := resolver.Resolve(context.Background(), root, graph, nil); err == nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("aggregate binding budget error = %v", err)
	}
}

func TestResolverRejectsExcessiveRepositoryPathDepth(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	limits := defaultResolverLimits()
	limits.maxModulePathSegments = 3
	resolver := newResolverWithLimits(NewInventoryBuilder(), newAliasInventoryBuilder(), limits)
	graph := modulegraph.Graph{Modules: []modulegraph.Module{{Path: "a/b/c/index.ts", Dialect: modulegraph.DialectTypeScript}}}
	if _, err := resolver.Resolve(context.Background(), root, graph, nil); err == nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("path depth budget error = %v", err)
	}
}

func TestResolverAliasWorkBudgetFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{
		"name":    "root",
		"imports": map[string]any{"#a": "lodash", "#b": "react"},
	})
	limits := defaultResolverLimits()
	limits.maxAliasWork = 1
	resolver := newResolverWithLimits(NewInventoryBuilder(), newAliasInventoryBuilder(), limits)
	got, err := resolver.Resolve(context.Background(), root, graphWithExternal("src/index.ts", "#b"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusUnresolved || !hasCoverageKind(got.Coverage, jsresolution.CoverageMetadataBudgetExceeded) {
		t.Fatalf("alias work budget did not fail closed: %#v", got)
	}
}

func TestResolverCandidateBudgetFailsClosedWithoutTruncating(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "workspaces": []string{"packages/*"}})
	for _, name := range []string{"a", "b", "c"} {
		writeJSON(t, r2bJoin(root, "packages", name, "package.json"), map[string]any{"name": "dup"})
	}
	limits := defaultResolverLimits()
	limits.maxCandidates = 2
	resolver := newResolverWithLimits(NewInventoryBuilder(), newAliasInventoryBuilder(), limits)
	got, err := resolver.Resolve(context.Background(), root, graphWithExternal("src/index.ts", "dup"), nil)
	if err != nil {
		t.Fatal(err)
	}
	resolution := got.Imports[0]
	if resolution.Status != jsresolution.StatusUnresolved || len(resolution.Candidates) != 0 || !hasCoverageKind(got.Coverage, jsresolution.CoverageMetadataBudgetExceeded) {
		t.Fatalf("candidate overflow was truncated instead of failing closed: resolution=%#v coverage=%#v", resolution, got.Coverage)
	}
}

func TestResolverAggregateCandidateWorkFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root", "workspaces": []string{"packages/*"}})
	writeJSON(t, r2bJoin(root, "packages", "shared", "package.json"), map[string]any{"name": "@repo/shared"})
	limits := defaultResolverLimits()
	limits.maxCandidateWork = 3
	resolver := newResolverWithLimits(NewInventoryBuilder(), newAliasInventoryBuilder(), limits)
	graph := modulegraph.Graph{
		Modules: []modulegraph.Module{{Path: "src/index.ts", Dialect: modulegraph.DialectTypeScript}},
		Edges: []modulegraph.Edge{
			{From: "src/index.ts", Specifier: "@repo/shared", Kind: modulegraph.ImportESMStatic},
			{From: "src/index.ts", Specifier: "@repo/shared/sub", Kind: modulegraph.ImportCommonJS},
		},
	}
	got, err := resolver.Resolve(context.Background(), root, graph, nil)
	if err != nil {
		t.Fatal(err)
	}
	ambiguous, budgeted := 0, 0
	for _, resolution := range got.Imports {
		switch {
		case resolution.Status == jsresolution.StatusAmbiguous:
			ambiguous++
		case resolution.Status == jsresolution.StatusUnresolved && resolution.Reason == "package identity candidate work budget exceeded":
			budgeted++
		}
	}
	if ambiguous != 1 || budgeted != 1 || !hasCoverageKind(got.Coverage, jsresolution.CoverageMetadataBudgetExceeded) {
		t.Fatalf("aggregate candidate work did not fail closed: %#v", got)
	}
}

func TestResolverSamePackageNameDoesNotBecomeThirdPartyWithoutExportsSemantics(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "my-app"})
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "my-app/subpath"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Imports[0].Status != jsresolution.StatusUnresolved || got.Imports[0].Package.Name != "my-app" || !hasCoverageKind(got.Coverage, jsresolution.CoverageUnresolvedSpecifier) {
		t.Fatalf("same-package self reference was treated as ordinary third-party: %#v", got)
	}
}
