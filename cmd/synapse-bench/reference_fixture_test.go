package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPublishedBenchmarkReplay(t *testing.T) {
	root := publishedBenchmarkFixtureRoot(t)
	observations := []string{
		"observations/debian-12-13-slim-amd64--grype.json",
		"observations/debian-12-13-slim-amd64--osv-scanner.json",
		"observations/debian-12-13-slim-amd64--owned.json",
		"observations/debian-12-13-slim-amd64--trivy.json",
		"observations/sles-15-6-bci-base-amd64--grype.json",
		"observations/sles-15-6-bci-base-amd64--osv-scanner-unsupported.json",
		"observations/sles-15-6-bci-base-amd64--owned.json",
		"observations/sles-15-6-bci-base-amd64--trivy.json",
	}
	fixtureResult, err := os.ReadFile(filepath.Join(root, "result.json"))
	if err != nil {
		t.Fatal(err)
	}

	arguments := func(output string) []string {
		args := []string{
			"-mode", "sca-accuracy",
			"-catalog", filepath.Join(root, "catalog.json"),
			"-oracle", filepath.Join(root, "oracle.json"),
			"-ratchet", filepath.Join(root, "ratchet.json"),
			"-output", output,
		}
		for _, observation := range observations {
			args = append(args, "-observation", filepath.Join(root, filepath.FromSlash(observation)))
		}
		return args
	}

	first := filepath.Join(t.TempDir(), "first.json")
	second := filepath.Join(t.TempDir(), "second.json")
	for _, output := range []string{first, second} {
		var stderr bytes.Buffer
		if code := executeCLI(arguments(output), strings.NewReader(""), &bytes.Buffer{}, &stderr); code != 0 {
			t.Fatalf("published benchmark replay exit code = %d, stderr = %q", code, stderr.String())
		}
	}
	firstBody, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondBody, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBody, secondBody) {
		t.Fatal("fresh published benchmark outputs differ")
	}
	if !bytes.Equal(firstBody, fixtureResult) {
		t.Fatal("published benchmark replay differs from checked-in result.json")
	}
}

func publishedBenchmarkFixtureRoot(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve published benchmark fixture root from runtime caller")
	}
	return filepath.Join(filepath.Dir(sourceFile), "..", "..", "internal", "usecase", "scabench", "testdata", "reference")
}
