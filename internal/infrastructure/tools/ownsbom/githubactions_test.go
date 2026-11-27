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
  reuse:
    uses: org/shared/.github/workflows/build.yml@v1.2.0
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4.1.7
      - name: download
        uses: "actions/download-artifact@v4.1.2"   # a comment
      - uses: actions/setup-go@v5
      - uses: github/codeql-action/upload-sarif@3.25.0
      - uses: actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94ea4f9
      - uses: Actions/Upload-Artifact@V4.3.1
      - uses: ./local-action
      - uses: docker://alpine:3.19
      - uses: actions/checkout@v4.1.7
      - run: |
          - uses: heredoc/inside@v9.9.9
      - uses: actions/github-script@v7.0.1
        with:
          uses: inwith/value@v2.0.0
          script: |
            uses: block/scalar@v3.0.0
`)
	comps, deps, err := GitHubActions{}.Parse(context.Background(), ParseInput{Path: ".github/workflows/ci.yml", Content: workflow})
	if err != nil || deps != nil {
		t.Fatalf("parse: %v %v", err, deps)
	}
	want := map[string]string{
		"org/shared":                "1.2.0", // a reusable workflow runs code from its repository
		"actions/upload-artifact":   "4.3.1", // owner and repository are lower-cased, V accepted
		"actions/github-script":     "7.0.1",
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
		".github/workflows/ci.yml":         true,
		".github/workflows/release.YAML":   true,
		".github/actions/setup/action.yml": true,
		"action.yaml":                      true,
		// GitHub runs only the root workflows directory; a nested one is a fixture or a template.
		"svc/.github/workflows/build.yaml":  false,
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

func TestGitHubActionsSkipsAnUnparseableActionManifest(t *testing.T) {
	comps, _, err := GitHubActions{}.Parse(context.Background(), ParseInput{Path: "testdata/action.yml", Content: []byte("runs: [unclosed")})
	if err != nil || len(comps) != 0 {
		t.Fatalf("an unparseable action.yml: comps %v err %v, want skipped", comps, err)
	}
	if _, _, err := (GitHubActions{}).Parse(context.Background(), ParseInput{Path: ".github/workflows/ci.yml", Content: []byte("jobs: [unclosed")}); err == nil {
		t.Fatal("an unparseable root workflow was accepted silently")
	}
}
