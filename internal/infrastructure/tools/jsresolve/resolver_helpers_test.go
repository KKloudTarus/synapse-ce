package jsresolve

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
)

func graphWithExternal(from, specifier string) modulegraph.Graph {
	return modulegraph.Graph{
		Modules: []modulegraph.Module{{Path: from, Dialect: modulegraph.DialectTypeScript}},
		Edges:   []modulegraph.Edge{{From: from, Specifier: specifier, Kind: modulegraph.ImportESMStatic}},
	}
}

func resolutionsBySpecifier(values []jsresolution.ImportResolution) map[string]jsresolution.ImportResolution {
	out := make(map[string]jsresolution.ImportResolution, len(values))
	for _, value := range values {
		out[value.Specifier] = value
	}
	return out
}

func r2bJoin(parts ...string) string {
	return filepath.Join(parts...)
}

func TestPackageForRepositoryTargetUsesDeepestSortedAncestor(t *testing.T) {
	t.Parallel()
	packages := []jsresolution.PackageMetadata{
		{Name: "root", Path: "."},
		{Name: "container", Path: "packages"},
		{Name: "app", Path: "packages/app"},
	}
	got, ok := packageForRepositoryTarget(packages, "packages/app/src/index.ts")
	if !ok || got.Path != "packages/app" || got.Name != "app" {
		t.Fatalf("nearest package = %#v, %v", got, ok)
	}
	got, ok = packageForRepositoryTarget(packages, "src/index.ts")
	if !ok || got.Path != "." || got.Name != "root" {
		t.Fatalf("root package = %#v, %v", got, ok)
	}
}

func TestPackageContextForImporterUsesNearestSortedScope(t *testing.T) {
	t.Parallel()
	contexts := []aliasPackageContext{
		{source: "package.json", scopeDir: ".", importsPresent: true},
		{source: "packages/app/package.json", scopeDir: "packages/app", importsPresent: true},
	}
	got, ok := packageContextForImporter(contexts, "packages/app/src/index.ts")
	if !ok || got.scopeDir != "packages/app" {
		t.Fatalf("nearest package scope = %#v, %v", got, ok)
	}
	got, ok = packageContextForImporter(contexts, "src/index.ts")
	if !ok || got.scopeDir != "." {
		t.Fatalf("root package scope = %#v, %v", got, ok)
	}
}

func TestRelativeEdgeCoverageLookupRequiresMatchingLineWhenPresent(t *testing.T) {
	t.Parallel()
	coverage := []modulegraph.CoverageIssue{
		{Kind: modulegraph.CoverageUnresolvedRelativeImport, Path: "src/index.ts", Line: 8, Detail: "first"},
		{Kind: modulegraph.CoverageUnresolvedRelativeImport, Path: "src/index.ts", Line: 9, Detail: "second"},
	}
	edge := modulegraph.Edge{From: "src/index.ts", Position: modulegraph.Position{Line: 9}}
	if !relativeEdgeHasCoverage(coverage, edge) {
		t.Fatal("matching line was not found")
	}
	edge.Position.Line = 10
	if relativeEdgeHasCoverage(coverage, edge) {
		t.Fatal("different line incorrectly matched coverage")
	}
	edge.Position.Line = 0
	if !relativeEdgeHasCoverage(coverage, edge) {
		t.Fatal("line-less edge did not match source coverage")
	}
}

func TestResolverUnknownNodeSchemeDoesNotBecomeBuiltin(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, r2bJoin(root, "package.json"), map[string]any{"name": "root"})
	got, err := NewResolver().Resolve(context.Background(), root, graphWithExternal("src/index.ts", "node:not-a-real-builtin"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Imports) != 1 || got.Imports[0].Status != jsresolution.StatusUnsupported || got.Complete ||
		!hasCoverageKind(got.Coverage, jsresolution.CoverageUnsupportedSpecifier) {
		t.Fatalf("unknown node: specifier was trusted as builtin: %#v", got)
	}
}
