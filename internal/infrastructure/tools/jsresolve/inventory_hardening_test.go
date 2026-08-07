package jsresolve

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
)

func TestInventoryBuilderPNPMSameIndentSequence(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pnpm-workspace.yaml"), "packages:\n- 'apps/*'\n- 'libs/*'\n")
	writeJSON(t, filepath.Join(root, "apps", "web", "package.json"), map[string]any{"name": "web"})
	writeJSON(t, filepath.Join(root, "libs", "shared", "package.json"), map[string]any{"name": "shared"})

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete {
		t.Fatalf("Complete = false; coverage=%#v", got.Coverage)
	}
	byPath := packagesByPath(got.Packages)
	if !byPath["apps/web"].Workspace || !byPath["libs/shared"].Workspace {
		t.Fatalf("same-indent pnpm workspaces not detected: %#v", byPath)
	}
}

func TestInventoryBuilderPNPMMalformedCannotLookComplete(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		content string
	}{
		{name: "empty body", content: "packages:\nother: value\n"},
		{name: "tab indent", content: "packages:\n\t- 'apps/*'\n"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeFile(t, filepath.Join(root, "pnpm-workspace.yaml"), test.content)
			writeJSON(t, filepath.Join(root, "apps", "web", "package.json"), map[string]any{"name": "web"})
			got, err := NewInventoryBuilder().Build(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if got.Complete || !coverageKinds(got.Coverage)[jsresolution.CoverageMalformedMetadata] {
				t.Fatalf("malformed pnpm metadata was treated as complete: %#v", got)
			}
		})
	}
}

func TestInventoryBuilderNegationIsOrderIndependent(t *testing.T) {
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
		t.Fatalf("Complete = false; coverage=%#v", got.Coverage)
	}
	byPath := packagesByPath(got.Packages)
	if !byPath["packages/public"].Workspace || byPath["packages/private/secret"].Workspace {
		t.Fatalf("negation order changed semantics: %#v", byPath)
	}
}

func TestWorkspaceMatcherAdversarialPatternIsBounded(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	parts := make([]string, 0, 29)
	for i := 0; i < 14; i++ {
		parts = append(parts, "**", "a")
	}
	parts = append(parts, "pkg")
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{"workspaces": []string{strings.Join(parts, "/")}})
	deep := root
	for i := 0; i < 24; i++ {
		deep = filepath.Join(deep, "b")
	}
	writeJSON(t, filepath.Join(deep, "package.json"), map[string]any{"name": "deep"})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := NewInventoryBuilder().Build(ctx, root)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("memoized matcher did not complete before the deadline: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Build did not return within the adversarial matcher time bound")
	}

	cancelled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if _, err := matchWorkspacePattern(cancelled, "**/pkg", "a/b/pkg"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled matcher error = %v, want context.Canceled", err)
	}
}

func TestWorkspacePatternErrorsUseSentinels(t *testing.T) {
	t.Parallel()
	if _, _, err := normalizeWorkspacePattern(".", "../escape", 32); !errors.Is(err, errWorkspaceRootEscape) {
		t.Fatalf("root escape error = %v", err)
	}
	if _, _, err := normalizeWorkspacePattern(".", `C:\outside\*`, 32); !errors.Is(err, errWorkspaceAbsolutePath) {
		t.Fatalf("absolute path error = %v", err)
	}
}

func TestInventoryBuilderPOSIXNamesAreNotWindowsPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX filename semantics")
	}
	t.Parallel()
	root := t.TempDir()
	writeJSON(t, filepath.Join(root, "c:tmp", "package.json"), map[string]any{"name": "colon"})
	writeJSON(t, filepath.Join(root, `packages\private`, "package.json"), map[string]any{"name": "backslash"})
	writeJSON(t, filepath.Join(root, "packages", "private", "package.json"), map[string]any{"name": "slash"})

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Complete {
		t.Fatalf("Complete = false; coverage=%#v", got.Coverage)
	}
	byPath := packagesByPath(got.Packages)
	for _, want := range []string{"c:tmp", `packages\private`, "packages/private"} {
		if _, ok := byPath[want]; !ok {
			t.Fatalf("missing distinct POSIX package path %q in %#v", want, byPath)
		}
	}
}

func TestInventoryBuilderSymlinkedMetadataFileAndDirectoryAreCovered(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not reliably available on Windows CI")
	}
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	writeJSON(t, filepath.Join(root, "package.json"), map[string]any{"workspaces": []string{"packages/*"}})
	writeJSON(t, filepath.Join(outside, "package.json"), map[string]any{"name": "outside"})
	if err := os.MkdirAll(filepath.Join(root, "tools"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "package.json"), filepath.Join(root, "packages.json.link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "tools", "shared")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "package.json"), filepath.Join(root, "package-link.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "linked-meta"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "package.json"), filepath.Join(root, "linked-meta", "package.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	got, err := NewInventoryBuilder().Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Complete || !coverageKinds(got.Coverage)[jsresolution.CoverageSymlinkWorkspace] {
		t.Fatalf("symlink coverage = %#v", got.Coverage)
	}
	if _, ok := packagesByPath(got.Packages)["linked-meta"]; ok {
		t.Fatal("symlinked package.json file was followed")
	}
}

func TestReadBoundedMetadataRejectsIdentityChange(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a"), "a")
	writeFile(t, filepath.Join(root, "b"), "b")
	info, err := os.Stat(filepath.Join(root, "a"))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = opened.Close() }()
	if _, err := readBoundedMetadata(opened, "b", info, 1024, 1024); !errors.Is(err, errMetadataChanged) {
		t.Fatalf("identity change error = %v", err)
	}
}

func TestInventoryBuilderLimitsAreInjectableAndHonest(t *testing.T) {
	t.Parallel()
	t.Run("metadata file size", func(t *testing.T) {
		limits := defaultInventoryLimits()
		limits.maxMetadataFileBytes = 16
		root := t.TempDir()
		writeJSON(t, filepath.Join(root, "package.json"), map[string]any{"name": strings.Repeat("x", 64)})
		assertBudgetCoverage(t, newInventoryBuilderWithLimits(limits), root)
	})

	t.Run("aggregate metadata bytes", func(t *testing.T) {
		limits := defaultInventoryLimits()
		limits.maxTotalMetadataBytes = 60
		root := t.TempDir()
		writeJSON(t, filepath.Join(root, "a", "package.json"), map[string]any{"name": "aaaaaaaaaaaaaaaa"})
		writeJSON(t, filepath.Join(root, "b", "package.json"), map[string]any{"name": "bbbbbbbbbbbbbbbb"})
		writeJSON(t, filepath.Join(root, "c", "package.json"), map[string]any{"name": "cccccccccccccccc"})
		assertBudgetCoverage(t, newInventoryBuilderWithLimits(limits), root)
	})

	t.Run("metadata files", func(t *testing.T) {
		limits := defaultInventoryLimits()
		limits.maxMetadataFiles = 1
		root := t.TempDir()
		writeJSON(t, filepath.Join(root, "a", "package.json"), map[string]any{"name": "a"})
		writeJSON(t, filepath.Join(root, "b", "package.json"), map[string]any{"name": "b"})
		assertBudgetCoverage(t, newInventoryBuilderWithLimits(limits), root)
	})

	t.Run("entries", func(t *testing.T) {
		limits := defaultInventoryLimits()
		limits.maxEntries = 2
		root := t.TempDir()
		writeJSON(t, filepath.Join(root, "a", "package.json"), map[string]any{"name": "a"})
		writeJSON(t, filepath.Join(root, "b", "package.json"), map[string]any{"name": "b"})
		assertBudgetCoverage(t, newInventoryBuilderWithLimits(limits), root)
	})

	t.Run("patterns per source", func(t *testing.T) {
		limits := defaultInventoryLimits()
		limits.maxPatternsPerSource = 1
		root := t.TempDir()
		writeJSON(t, filepath.Join(root, "package.json"), map[string]any{"workspaces": []string{"a/*", "b/*"}})
		writeJSON(t, filepath.Join(root, "a", "one", "package.json"), map[string]any{"name": "one"})
		assertBudgetCoverage(t, newInventoryBuilderWithLimits(limits), root)
	})

	t.Run("total patterns", func(t *testing.T) {
		limits := defaultInventoryLimits()
		limits.maxPatternsTotal = 1
		root := t.TempDir()
		writeJSON(t, filepath.Join(root, "package.json"), map[string]any{"workspaces": []string{"a/*"}})
		writeJSON(t, filepath.Join(root, "nested", "package.json"), map[string]any{"workspaces": []string{"b/*"}})
		assertBudgetCoverage(t, newInventoryBuilderWithLimits(limits), root)
	})

	t.Run("coverage slice", func(t *testing.T) {
		limits := defaultInventoryLimits()
		limits.maxCoverageIssues = 2
		root := t.TempDir()
		writeJSON(t, filepath.Join(root, "package.json"), map[string]any{"workspaces": []string{"../a", "../b", "../c"}})
		got, err := newInventoryBuilderWithLimits(limits).Build(context.Background(), root)
		if err != nil {
			t.Fatal(err)
		}
		if got.Complete || len(got.Coverage) > limits.maxCoverageIssues || !coverageKinds(got.Coverage)[jsresolution.CoverageMetadataBudgetExceeded] {
			t.Fatalf("coverage cap was not enforced: %#v", got.Coverage)
		}
	})

	t.Run("workspace match work", func(t *testing.T) {
		limits := defaultInventoryLimits()
		limits.maxWorkspaceMatchWork = 1
		root := t.TempDir()
		writeJSON(t, filepath.Join(root, "package.json"), map[string]any{"workspaces": []string{"**"}})
		writeJSON(t, filepath.Join(root, "a", "package.json"), map[string]any{"name": "a"})
		writeJSON(t, filepath.Join(root, "b", "package.json"), map[string]any{"name": "b"})
		assertBudgetCoverage(t, newInventoryBuilderWithLimits(limits), root)
	})
}

func assertBudgetCoverage(t *testing.T, builder *InventoryBuilder, root string) {
	t.Helper()
	got, err := builder.Build(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Complete || !coverageKinds(got.Coverage)[jsresolution.CoverageMetadataBudgetExceeded] {
		t.Fatalf("budget exhaustion did not make inventory incomplete: %#v", got)
	}
}

func TestCandidateIndexAvoidsUnboundedCartesianProduct(t *testing.T) {
	t.Parallel()
	patterns := []compiledPattern{
		{source: "package.json", pattern: "packages/a/*", match: "packages/a/*"},
		{source: "package.json", pattern: "packages/b/*", match: "packages/b/*"},
	}
	dirs := make([]string, 0, 2000)
	for i := 0; i < 1000; i++ {
		dirs = append(dirs, fmt.Sprintf("other/%04d", i))
	}
	for i := 0; i < 1000; i++ {
		dirs = append(dirs, fmt.Sprintf("packages/a/%04d", i))
	}
	sort.Strings(dirs)
	budget := workBudget{remaining: 1100}
	got := candidatePackageDirs(patterns, dirs, &budget)
	if budget.exceeded {
		t.Fatal("literal-prefix candidate index consumed the full cartesian-product budget")
	}
	if len(got) != 1000 {
		t.Fatalf("candidate count = %d, want 1000", len(got))
	}
}
