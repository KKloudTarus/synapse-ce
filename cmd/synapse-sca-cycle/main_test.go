package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrustedRunUsesCancellationContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	if code := executeCLIContext(ctx, []string{"run"}, &stdout, &stderr); code != 1 {
		t.Fatalf("canceled trusted run exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), context.Canceled.Error()) {
		t.Fatalf("canceled trusted run error = %q, want context cancellation", stderr.String())
	}
}

func TestExecuteCLIRoutesCandidateAndTrustedCommands(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{name: "no command", code: 1},
		{name: "unknown command", args: []string{"unknown"}, code: 1},
		{name: "trusted help", args: []string{"run", "--help"}, code: 0},
		{name: "candidate help", args: []string{"candidate", "--help"}, code: 0},
		{name: "candidate missing input", args: []string{"candidate", "--evidence-root", "/protected"}, code: 1},
		{name: "candidate bundle missing attestation", args: []string{"candidate", "--input-bundle", "/bundle", "--evidence-root", "/protected"}, code: 1},
		{name: "candidate inputs conflict", args: []string{"candidate", "--offline-input-root", "/inputs", "--input-bundle", "/bundle", "--environment-attestation", "/attestation", "--evidence-root", "/protected"}, code: 1},
		{name: "candidate positional input", args: []string{"candidate", "unrecognized"}, code: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := executeCLI(tc.args, &stdout, &stderr); code != tc.code {
				t.Fatalf("executeCLI(%q) = %d, want %d; stderr: %s", tc.args, code, tc.code, stderr.String())
			}
		})
	}
}

func TestCandidateCheckoutRejectsUncommittedChanges(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is unavailable")
	}
	root := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		command := exec.Command("git", append([]string{"-C", root}, args...)...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %q: %v: %s", args, err, output)
		}
	}
	runGit("init", "-q")
	expectedCorpus := filepath.Join(root, "internal", "usecase", "scabench", "corpus")
	if err := os.MkdirAll(expectedCorpus, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(expectedCorpus, "fixture.txt")
	if err := os.WriteFile(marker, []byte("frozen"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit("add", "internal/usecase/scabench/corpus/fixture.txt")
	runGit("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "fixture")
	corpus, commit, err := candidateCheckout(root)
	if err != nil {
		t.Fatalf("resolve clean candidate checkout: %v", err)
	}
	actualCorpusInfo, actualErr := os.Stat(corpus)
	expectedCorpusInfo, expectedErr := os.Stat(expectedCorpus)
	if actualErr != nil || expectedErr != nil || !os.SameFile(actualCorpusInfo, expectedCorpusInfo) || len(commit) != 40 {
		t.Fatalf("unexpected clean candidate identity: corpus=%q commit=%q", corpus, commit)
	}
	if err := os.WriteFile(marker, []byte("modified"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := candidateCheckout(root); err == nil || !strings.Contains(err.Error(), "clean source checkout") {
		t.Fatalf("dirty candidate checkout error = %v, want clean-source failure", err)
	}
}

func TestCandidateRunKeyIsUniqueAndPortable(t *testing.T) {
	first, err := candidateRunKey()
	if err != nil {
		t.Fatal(err)
	}
	second, err := candidateRunKey()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !strings.HasPrefix(first, "candidate/") || strings.ContainsAny(first, " \\:") {
		t.Fatalf("candidate run keys are not unique portable paths: %q %q", first, second)
	}
}
