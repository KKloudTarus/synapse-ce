package benchid

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const committedManifestPath = "../../../docs/benchmarks/competitor-identity.json"

// TestCommittedManifestIsValid is the drift guard for the committed competitor-identity manifest: it must load,
// carry the current schema, and record a complete identity (version, ruleset, source, dimension, scope notes)
// for every competitor differential the repository ships. This runs without any competitor binary present, so
// the recorded identity is verified in every CI run, not only when a competitor happens to be installed.
func TestCommittedManifestIsValid(t *testing.T) {
	m, err := Load(committedManifestPath)
	if err != nil {
		t.Fatalf("committed manifest must load: %v", err)
	}
	// Every differential shipped in the tree must have a recorded identity here.
	for _, tool := range []string{"gitleaks", "checkov"} {
		id, ok := m.Expected(tool)
		if !ok {
			t.Errorf("manifest is missing an identity for %q (a shipped differential has no recorded competitor identity)", tool)
			continue
		}
		if id.Version == "" || id.Ruleset == "" || id.Source == "" || id.Dimension == "" || id.ScopeNotes == "" {
			t.Errorf("%s identity is incomplete: %+v (version/ruleset/source/dimension/scope_notes are all required)", tool, id)
		}
	}
}

func TestLoadRejectsWrongSchema(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(p, []byte(`{"schema":"nope","competitors":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Error("a manifest with the wrong schema must be rejected")
	}
}

func TestVersionMatches(t *testing.T) {
	cases := []struct {
		observed, pinned string
		want             bool
	}{
		{"gitleaks 8.30.1", "8.30.1", true}, // banner with tool name
		{"v8.30.1", "8.30.1", true},         // leading v
		{"3.3.19", "3.3.19", true},          // bare version
		{"3.3.19", "3.3.1", false},          // the substring trap: 3.3.19 must NOT match pinned 3.3.1
		{"3.3.1", "3.3.19", false},          // reverse drift
		{"gitleaks version 8.30.0", "8.30.1", false},
		{`checkov "2.5.0"`, "2.5.0", true}, // quoted token
		{"anything", "", false},            // empty pinned never matches
	}
	for _, c := range cases {
		if got := VersionMatches(c.observed, c.pinned); got != c.want {
			t.Errorf("VersionMatches(%q,%q)=%v want %v", c.observed, c.pinned, got, c.want)
		}
	}
}

func TestCaptureVersionReportsAbsentTool(t *testing.T) {
	// A tool that is not installed must return an error, not a fabricated version, so a differential records
	// "identity unrecorded" rather than a wrong identity.
	if v, err := CaptureVersion(context.Background(), "definitely-not-a-real-binary-xyz", "version"); err == nil || v != "" {
		t.Errorf("absent tool must yield an error and empty version, got %q err=%v", v, err)
	}
}
