package benchcycle

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestValidateIdentityAndRoots(t *testing.T) {
	commit := strings.Repeat("a", 40)
	if err := ValidateIdentity(commit, "release-1/run_01"); err != nil {
		t.Fatalf("validate identity: %v", err)
	}
	for _, identity := range []struct {
		commit string
		runKey string
	}{
		{commit: strings.Repeat("A", 40), runKey: "release/run"},
		{commit: commit, runKey: "./run"},
		{commit: commit, runKey: "release/.."},
		{commit: commit, runKey: "release/../run"},
		{commit: commit, runKey: "release/run/again"},
	} {
		if err := ValidateIdentity(identity.commit, identity.runKey); err == nil {
			t.Fatalf("accepted invalid identity %+v", identity)
		}
	}
	if err := ValidateAbsolutePath("root", "relative"); err == nil {
		t.Fatal("accepted relative root")
	}
	output := filepath.Join(t.TempDir(), "output")
	if err := EnsureAbsent(output, "output root"); err != nil {
		t.Fatalf("accept absent output: %v", err)
	}
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := EnsureAbsent(output, "output root"); err == nil {
		t.Fatal("accepted existing output")
	}
}

func TestRealDirectoryAndBelowRootRejectUnsafePaths(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "asset.json")
	if err := os.WriteFile(file, []byte("asset"), 0o600); err != nil {
		t.Fatal(err)
	}
	actual, err := RealDirectory(root)
	if err != nil {
		t.Fatalf("real directory: %v", err)
	}
	if actual != root {
		t.Fatalf("real directory = %q, want %q", actual, root)
	}
	if path, err := BelowRoot(root, "asset.json"); err != nil || path != file {
		t.Fatalf("resolve regular asset = %q, %v", path, err)
	}
	if _, err := BelowRoot(root, "../asset.json"); err == nil {
		t.Fatal("accepted escaping asset")
	}
	link := filepath.Join(root, "asset-link.json")
	if err := os.Symlink(file, link); err != nil {
		t.Skipf("create symlink: %v", err)
	}
	if _, err := BelowRoot(root, "asset-link.json"); err == nil {
		t.Fatal("accepted symlink asset")
	}
}

func TestWorkspaceCleanupRemovesStateBeforeRuntimeCleanup(t *testing.T) {
	rawRoot := t.TempDir()
	workspace, err := PrepareWorkspace(rawRoot, "release/run")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(rawRoot, "release", "run"); workspace.RawRunRoot() != want {
		t.Fatalf("raw run root = %q, want %q", workspace.RawRunRoot(), want)
	}
	if !filepath.IsAbs(workspace.WorkRoot()) {
		t.Fatalf("work root is not absolute: %q", workspace.WorkRoot())
	}
	if err := os.MkdirAll(filepath.Dir(workspace.RawRunRoot()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workspace.RawRunRoot(), []byte("raw"), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	err = workspace.Cleanup(context.Background(), func(context.Context) error {
		called = true
		for _, path := range []string{workspace.RawRunRoot(), workspace.WorkRoot()} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("state %q remained before runtime cleanup: %v", path, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("cleanup workspace: %v", err)
	}
	if !called {
		t.Fatal("runtime cleanup was not called")
	}
}

func TestZeroWorkspaceRefusesCleanupWithoutRuntimeCallback(t *testing.T) {
	var workspace Workspace
	if err := workspace.RemoveWork(); err == nil {
		t.Fatal("zero workspace removed a path")
	}
	called := false
	if err := workspace.Cleanup(context.Background(), func(context.Context) error {
		called = true
		return nil
	}); err == nil {
		t.Fatal("zero workspace accepted cleanup")
	}
	if called {
		t.Fatal("zero workspace invoked runtime cleanup")
	}
}

func TestArtifactPrimitivesDoNotOverwriteOrPublishUnsafeStages(t *testing.T) {
	directory := t.TempDir()
	file := filepath.Join(directory, "nested", "artifact.json")
	if err := WriteNewFile(file, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteNewFile(file, []byte("second"), 0o600); err == nil {
		t.Fatal("overwrote an artifact")
	}
	body, err := os.ReadFile(file)
	if err != nil || string(body) != "first" {
		t.Fatalf("artifact contents = %q, %v", body, err)
	}

	stage := filepath.Join(directory, "stage")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(filepath.Join(stage, "artifact.json"), []byte("bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(directory, "bundle")
	if err := PublishDirectory(stage, output); err != nil {
		t.Fatalf("publish bundle: %v", err)
	}
	if _, err := os.Stat(filepath.Join(output, "artifact.json")); err != nil {
		t.Fatalf("published artifact: %v", err)
	}

	nextStage := filepath.Join(directory, "next-stage")
	if err := os.Mkdir(nextStage, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := PublishDirectory(nextStage, output); err == nil {
		t.Fatal("overwrote a published bundle")
	}

	link := filepath.Join(directory, "stage-link")
	if err := os.Symlink(output, link); err != nil {
		t.Skipf("create stage symlink: %v", err)
	}
	if err := PublishDirectory(link, filepath.Join(directory, "linked-output")); err == nil {
		t.Fatal("accepted a symlink staging directory")
	}
}

func TestExecuteRepeatedSupportsNonBenchmarkCallbacks(t *testing.T) {
	var captures []string
	var comparisons []string
	outcomes, err := ExecuteRepeated(context.Background(), 3, []string{"alpha", "beta"},
		func(_ context.Context, repetition int, cell string) (string, error) {
			outcome := fmt.Sprintf("%d:%s", repetition, cell)
			captures = append(captures, outcome)
			return outcome, nil
		},
		func(_ context.Context, cell string, cellOutcomes []string) error {
			comparisons = append(comparisons, fmt.Sprintf("%s=%s", cell, strings.Join(cellOutcomes, ",")))
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	wantOutcomes := [][]string{{"1:alpha", "1:beta"}, {"2:alpha", "2:beta"}, {"3:alpha", "3:beta"}}
	if !reflect.DeepEqual(outcomes, wantOutcomes) {
		t.Fatalf("outcomes = %#v, want %#v", outcomes, wantOutcomes)
	}
	if want := []string{"1:alpha", "1:beta", "2:alpha", "2:beta", "3:alpha", "3:beta"}; !reflect.DeepEqual(captures, want) {
		t.Fatalf("capture order = %#v, want %#v", captures, want)
	}
	if want := []string{"alpha=1:alpha,2:alpha,3:alpha", "beta=1:beta,2:beta,3:beta"}; !reflect.DeepEqual(comparisons, want) {
		t.Fatalf("comparison order = %#v, want %#v", comparisons, want)
	}
}
