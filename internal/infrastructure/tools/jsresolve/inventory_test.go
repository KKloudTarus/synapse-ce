package jsresolve

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
)

func TestInventoryBuilderPackageJSONWorkspaces(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{
		"name": "Root-App", "private": true, "workspaces": []string{"packages/*"},
	})
	writeJSON(t, filepath.Join(root, "packages", "a", "package.json"), map[string]any{"name": "@Scope/A", "version": "1.0.0"})
	writeJSON(t, filepath.Join(root, "packages", "b", "package.json"), map[string]any{"name": "b", "version": "2.0.0"})
	writeJSON(t, filepath.Join(root, "tools", "cli", "package.json"), map[string]any{"name": "cli"})
	writeJSON(t, filepath.Join(root, "node_modules", "ignored", "package.json"), map[string]any{"name": "ignored"})

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete {
		t.Fatalf("Complete = false; coverage=%#v", got.Coverage)
	}
	if len(got.Packages) != 4 {
		t.Fatalf("Packages = %d, want 4: %#v", len(got.Packages), got.Packages)
	}
	byPath := packagesByPath(got.Packages)
	if !byPath["packages/a"].Workspace || byPath["packages/a"].Name != "@scope/a" {
		t.Fatalf("packages/a = %#v", byPath["packages/a"])
	}
	if !byPath["packages/b"].Workspace || byPath["tools/cli"].Workspace {
		t.Fatalf("unexpected workspace flags: %#v", byPath)
	}
	if len(byPath["packages/a"].DeclaredBy) != 1 || byPath["packages/a"].DeclaredBy[0].Source != "package.json" {
		t.Fatalf("workspace provenance = %#v", byPath["packages/a"].DeclaredBy)
	}
}

func TestInventoryBuilderYarnWorkspaceObject(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{
		"private": true,
		"workspaces": map[string]any{"packages": []string{"apps/*"}},
	})
	writeJSON(t, filepath.Join(root, "apps", "web", "package.json"), map[string]any{"name": "web"})

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete || !packagesByPath(got.Packages)["apps/web"].Workspace {
		t.Fatalf("inventory = %#v", got)
	}
}

func TestInventoryBuilderPNPMWorkspaceWithNegation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pnpm-workspace.yaml"), "packages:\n  - 'packages/**'\n  - '!packages/private/**'\n")
	writeJSON(t, filepath.Join(root, "packages", "a", "package.json"), map[string]any{"name": "a"})
	writeJSON(t, filepath.Join(root, "packages", "group", "b", "package.json"), map[string]any{"name": "b"})
	writeJSON(t, filepath.Join(root, "packages", "private", "hidden", "package.json"), map[string]any{"name": "hidden"})

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete {
		t.Fatalf("Complete = false; coverage=%#v", got.Coverage)
	}
	byPath := packagesByPath(got.Packages)
	if !byPath["packages/a"].Workspace || !byPath["packages/group/b"].Workspace || byPath["packages/private/hidden"].Workspace {
		t.Fatalf("unexpected pnpm workspace flags: %#v", byPath)
	}
}

func TestInventoryBuilderIncompleteCoverage(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"workspaces":["../escape","packages/{a,b}","packages/*"]}`)
	writeFile(t, filepath.Join(root, "packages", "bad", "package.json"), `{bad json`)
	writeJSON(t, filepath.Join(root, "packages", "one", "package.json"), map[string]any{"name": "same"})
	writeJSON(t, filepath.Join(root, "packages", "two", "package.json"), map[string]any{"name": "same"})

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Complete {
		t.Fatal("Complete = true with incomplete metadata")
	}
	kinds := coverageKinds(got.Coverage)
	for _, want := range []jsresolution.CoverageIssueKind{
		jsresolution.CoverageMalformedMetadata,
		jsresolution.CoverageUnsupportedMetadata,
		jsresolution.CoverageWorkspaceRootEscape,
		jsresolution.CoverageWorkspaceNameConflict,
	} {
		if !kinds[want] {
			t.Fatalf("missing coverage kind %q in %#v", want, got.Coverage)
		}
	}
}

func TestInventoryBuilderSymlinkWorkspace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not reliably available on Windows CI")
	}
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{"workspaces": []string{"packages/*"}})
	writeJSON(t, filepath.Join(outside, "package.json"), map[string]any{"name": "outside"})
	if err := os.MkdirAll(filepath.Join(root, "packages"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "packages", "linked")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Complete || !coverageKinds(got.Coverage)[jsresolution.CoverageSymlinkWorkspace] {
		t.Fatalf("symlink coverage = %#v", got.Coverage)
	}
	if _, ok := packagesByPath(got.Packages)["packages/linked"]; ok {
		t.Fatal("symlinked workspace was followed")
	}
}

func TestInventoryBuilderDeterministic(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{"workspaces": []string{"packages/*"}})
	writeJSON(t, filepath.Join(root, "packages", "z", "package.json"), map[string]any{"name": "z"})
	writeJSON(t, filepath.Join(root, "packages", "a", "package.json"), map[string]any{"name": "a"})

	builder := NewInventoryBuilder()
	first, err := builder.Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 25; i++ {
		got, err := builder.Build(context.Background(), root)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d differs\nfirst=%#v\ngot=%#v", i, first, got)
		}
	}
}

func TestInventoryBuilderHardFailures(t *testing.T) {
	t.Parallel()
	builder := NewInventoryBuilder()
	if _, err := builder.Build(context.Background(), ""); err == nil {
		t.Fatal("empty root error = nil")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := builder.Build(ctx, t.TempDir()); err == nil {
		t.Fatal("cancelled context error = nil")
	}
	file := filepath.Join(t.TempDir(), "not-a-directory")
	writeFile(t, file, "x")
	if _, err := builder.Build(context.Background(), file); err == nil {
		t.Fatal("file root error = nil")
	}
}

func writeJSON(t *testing.T, file string, value any) {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, file, string(content))
}

func writeFile(t *testing.T, file, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func packagesByPath(packages []jsresolution.PackageMetadata) map[string]jsresolution.PackageMetadata {
	out := make(map[string]jsresolution.PackageMetadata, len(packages))
	for _, pkg := range packages {
		out[pkg.Path] = pkg
	}
	return out
}

func coverageKinds(issues []jsresolution.CoverageIssue) map[jsresolution.CoverageIssueKind]bool {
	out := make(map[jsresolution.CoverageIssueKind]bool, len(issues))
	for _, issue := range issues {
		out[issue.Kind] = true
	}
	return out
}
