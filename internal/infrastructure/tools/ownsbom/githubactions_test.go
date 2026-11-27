package ownsbom

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestGitHubActionsParsesUsesReferences(t *testing.T) {
	workflow := []byte(`name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4.1.7
      - name: download
        uses: "actions/download-artifact@v4.1.2"   # a comment
      - uses: actions/setup-go@v5
      - uses: github/codeql-action/upload-sarif@3.25.0
      - uses: actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94ea4f9
      - uses: ./local-action
      - uses: docker://alpine:3.19
      - uses: actions/checkout@v4.1.7
`)
	comps, deps, err := GitHubActions{}.Parse(context.Background(), ParseInput{Path: ".github/workflows/ci.yml", Content: workflow})
	if err != nil || deps != nil {
		t.Fatalf("parse: %v %v", err, deps)
	}
	want := map[string]string{
		"actions/checkout":          "4.1.7",
		"actions/download-artifact": "4.1.2",
		"actions/setup-go":          "v5", // a floating major tag is kept as written
		"github/codeql-action":      "3.25.0",
		"actions/cache":             "0c45773b623bea8c8e75f6c82b208c3cf94ea4f9",
	}
	if len(comps) != len(want) {
		t.Fatalf("components = %+v, want %d", comps, len(want))
	}
	for _, c := range comps {
		if want[c.Name] != c.Version {
			t.Errorf("%s = %q, want %q", c.Name, c.Version, want[c.Name])
		}
		if c.PURL != "pkg:githubactions/"+c.Name+"@"+c.Version || c.Scope != sbom.ScopeDevelopment {
			t.Errorf("%s: purl %q scope %q", c.Name, c.PURL, c.Scope)
		}
	}
}

func TestGitHubActionsRecognizesWorkflowsByPath(t *testing.T) {
	for rel, want := range map[string]bool{
		".github/workflows/ci.yml":          true,
		".github/workflows/release.YAML":    true,
		"svc/.github/workflows/build.yaml":  true,
		".github/workflows/nested/deep.yml": false,
		".github/dependabot.yml":            false,
		"docs/.github/workflows/readme.md":  false,
		"workflows/ci.yml":                  false,
	} {
		if got := (GitHubActions{}).MatchesPath(rel); got != want {
			t.Errorf("MatchesPath(%q) = %v, want %v", rel, got, want)
		}
	}
}

func TestRegistryCatalogsWorkflowActions(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anything.yml"), []byte("jobs:\n  a:\n    steps:\n      - uses: actions/download-artifact@v4.1.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := DefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := reg.Generate(context.Background(), root)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	found := false
	for _, c := range doc.Components {
		if c.PURL == "pkg:githubactions/actions/download-artifact@4.1.2" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the workflow's action was not cataloged: %+v", doc.Components)
	}
}
