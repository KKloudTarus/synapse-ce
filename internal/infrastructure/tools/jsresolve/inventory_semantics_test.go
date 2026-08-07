package jsresolve

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
)

func TestInventoryBuilderPNPMRootIsAlwaysWorkspace(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{"name": "root-pkg", "private": true})
	writeFile(t, filepath.Join(root, "pnpm-workspace.yaml"), "packages:\n  - 'packages/*'\n")
	writeJSON(t, filepath.Join(root, "packages", "child", "package.json"), map[string]any{"name": "child"})

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete {
		t.Fatalf("valid pnpm workspace unexpectedly incomplete: %#v", got.Coverage)
	}
	byPath := packagesByPath(got.Packages)
	if !byPath["."].Workspace || !byPath["packages/child"].Workspace {
		t.Fatalf("pnpm workspace membership = %#v", byPath)
	}
}

func TestInventoryBuilderPNPMOmittedPackagesMeansRootOnlyWorkspace(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{"name": "root-pkg", "private": true})
	writeFile(t, filepath.Join(root, "pnpm-workspace.yaml"), "catalog:\n  chalk: ^5.0.0\n")

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete {
		t.Fatalf("valid root-only pnpm workspace unexpectedly incomplete: %#v", got.Coverage)
	}
	if !packagesByPath(got.Packages)["."].Workspace {
		t.Fatalf("pnpm root-only workspace did not include root: %#v", got.Packages)
	}
}

func TestInventoryBuilderUnsupportedExtglobCannotLookComplete(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{
		"name": "root", "private": true, "workspaces": []string{"packages/@(a|b)"},
	})
	writeJSON(t, filepath.Join(root, "packages", "a", "package.json"), map[string]any{"name": "a"})
	writeJSON(t, filepath.Join(root, "packages", "b", "package.json"), map[string]any{"name": "b"})

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Complete || !coverageKinds(got.Coverage)[jsresolution.CoverageUnsupportedMetadata] {
		t.Fatalf("unsupported extglob was not explicit incomplete coverage: %#v", got)
	}
}

func TestInventoryBuilderUnsupportedPNPMYAMLCannotLookComplete(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{"name": "root", "private": true})
	writeFile(t, filepath.Join(root, "pnpm-workspace.yaml"), "packages:\n  - &workspace 'packages/*'\n")
	writeJSON(t, filepath.Join(root, "packages", "a", "package.json"), map[string]any{"name": "a"})

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Complete || !coverageKinds(got.Coverage)[jsresolution.CoverageMalformedMetadata] {
		t.Fatalf("unsupported YAML scalar syntax was not explicit incomplete coverage: %#v", got)
	}
}

func TestInventoryBuilderWorkspacePatternWhitespaceIsMeaningful(t *testing.T) {
	if filepath.Separator == '\\' {
		t.Skip("trailing-space path semantics are not portable to Windows")
	}
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{
		"name": "root", "private": true, "workspaces": []string{" packages/a "},
	})
	writeJSON(t, filepath.Join(root, " packages", "a ", "package.json"), map[string]any{"name": "spaced"})

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete {
		t.Fatalf("literal whitespace path unexpectedly incomplete: %#v", got.Coverage)
	}
	if !packagesByPath(got.Packages)[" packages/a "].Workspace {
		t.Fatalf("workspace pattern whitespace was not preserved: %#v", got.Packages)
	}
}

func TestInventoryBuilderNPMOrderedNegationCanReinclude(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{
		"name": "root", "private": true, "packageManager": "npm@12.0.1",
		"workspaces": []string{"packages/**", "!packages/b/**", "packages/b/a"},
	})
	writeJSON(t, filepath.Join(root, "packages", "b", "a", "package.json"), map[string]any{"name": "a"})

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete {
		t.Fatalf("valid npm workspace unexpectedly incomplete: %#v", got.Coverage)
	}
	if !packagesByPath(got.Packages)["packages/b/a"].Workspace {
		t.Fatalf("npm positive pattern did not re-include workspace: %#v", got.Packages)
	}
}

func TestInventoryBuilderDefaultNegationRemainsOrderIndependent(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{
		"workspaces": []string{"!packages/private/**", "packages/**"},
	})
	writeJSON(t, filepath.Join(root, "packages", "public", "package.json"), map[string]any{"name": "public"})
	writeJSON(t, filepath.Join(root, "packages", "private", "secret", "package.json"), map[string]any{"name": "secret"})

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete {
		t.Fatalf("default workspace semantics unexpectedly incomplete: %#v", got.Coverage)
	}
	byPath := packagesByPath(got.Packages)
	if !byPath["packages/public"].Workspace || byPath["packages/private/secret"].Workspace {
		t.Fatalf("default order-independent exclusion regressed: %#v", byPath)
	}
}
