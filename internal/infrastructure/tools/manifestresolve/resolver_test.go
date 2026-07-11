package manifestresolve

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoOpWithoutManifest(t *testing.T) {
	for _, eco := range []string{"composer", "gem", "poetry"} {
		comps, err := New(eco, "").Resolve(context.Background(), t.TempDir())
		if err != nil || comps != nil {
			t.Errorf("%s: no manifest must be a no-op; got %d comps err=%v", eco, len(comps), err)
		}
	}
}

func TestNoOpWhenLockfilePresent(t *testing.T) {
	cases := map[string][2]string{ // ecosystem -> {manifest, committed lockfile}
		"composer": {"composer.json", "composer.lock"},
		"gem":      {"Gemfile", "Gemfile.lock"},
		"poetry":   {"pyproject.toml", "poetry.lock"},
	}
	for eco, f := range cases {
		dir := t.TempDir()
		must(t, filepath.Join(dir, f[0]), "{}")
		must(t, filepath.Join(dir, f[1]), "{}")
		// Bad bin proves the tool is never invoked when a lockfile already exists.
		comps, err := New(eco, "/nonexistent/tool").Resolve(context.Background(), dir)
		if err != nil || comps != nil {
			t.Errorf("%s: committed lockfile must short-circuit; got %d comps err=%v", eco, len(comps), err)
		}
	}
}

func TestUnknownEcosystemIsNoOp(t *testing.T) {
	dir := t.TempDir()
	must(t, filepath.Join(dir, "whatever"), "x")
	if comps, err := New("golang", "go").Resolve(context.Background(), dir); err != nil || comps != nil {
		t.Errorf("unknown ecosystem must be a no-op; got %d comps err=%v", len(comps), err)
	}
}

func TestEcosystemLabelAndSpecs(t *testing.T) {
	for eco, want := range map[string]string{"composer": "composer", "gem": "gem", "poetry": "poetry"} {
		if got := New(eco, "").Ecosystem(); got != want {
			t.Errorf("Ecosystem() = %q, want %q", got, want)
		}
	}
	// Every spec must run in a no-scripts / lock-only mode (safety-critical, per ecosystem).
	for eco, s := range specs {
		joined := strings.Join(s.args, " ")
		switch eco {
		case "composer":
			if !strings.Contains(joined, "--no-scripts") || !strings.Contains(joined, "--no-install") {
				t.Errorf("composer args must be no-scripts + no-install: %q", joined)
			}
		case "gem", "poetry":
			if !strings.Contains(joined, "lock") || strings.Contains(joined, "install") {
				t.Errorf("%s args must be lock-only (no install): %q", eco, joined)
			}
		}
	}
}

func TestScrubSensitiveEnv(t *testing.T) {
	out := scrubSensitiveEnv([]string{"PATH=/x", "HOME=/h", "NPM_TOKEN=s", "AWS_SECRET_ACCESS_KEY=s", "SYNAPSE_DB_DSN=s", "GITHUB_TOKEN=s"})
	if len(out) != 2 {
		t.Errorf("only PATH+HOME must survive, got %v", out)
	}
}

func must(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
