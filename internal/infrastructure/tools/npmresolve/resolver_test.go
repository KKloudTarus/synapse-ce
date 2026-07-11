package npmresolve

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveNoOpWithoutPackageJSON(t *testing.T) {
	comps, err := New("npm").Resolve(context.Background(), t.TempDir())
	if err != nil || comps != nil {
		t.Errorf("no package.json must be a no-op (nil, nil); got %d comps, err=%v", len(comps), err)
	}
}

func TestResolveNoOpWhenLockfilePresent(t *testing.T) {
	// A committed lockfile is parsed directly by the owned parser, so the resolver must NOT run npm
	// (redundant, and it would waste a network round trip). Uses a bad bin to prove npm is never invoked.
	for _, lock := range lockfileNames {
		dir := t.TempDir()
		write(t, filepath.Join(dir, "package.json"), `{"name":"x","version":"1.0.0"}`)
		write(t, filepath.Join(dir, lock), "{}")
		comps, err := New("/nonexistent/npm-should-never-run").Resolve(context.Background(), dir)
		if err != nil || comps != nil {
			t.Errorf("%s present must short-circuit to (nil, nil); got %d comps, err=%v", lock, len(comps), err)
		}
	}
}

func TestArgsAreScriptSafe(t *testing.T) {
	got := strings.Join(New("npm").args(), " ")
	for _, must := range []string{"--ignore-scripts", "--package-lock-only"} {
		if !strings.Contains(got, must) {
			t.Errorf("resolver args MUST contain %q (safety-critical); got %q", must, got)
		}
	}
	// No build/install of node_modules and no arbitrary run.
	if strings.Contains(got, "run ") || strings.Contains(got, "exec") {
		t.Errorf("resolver args must not run scripts/exec; got %q", got)
	}
}

func TestScrubSensitiveEnv(t *testing.T) {
	in := []string{
		"PATH=/usr/bin", "HOME=/h", // kept
		"SYNAPSE_LLM_API_KEY=x", "SYNAPSE_DB_DSN=x", // Synapse
		"NPM_TOKEN=x", "NODE_AUTH_TOKEN=x", "GITHUB_TOKEN=x", // registry/CI
		"AWS_SECRET_ACCESS_KEY=x", "AWS_ACCESS_KEY_ID=x", "DB_PASSWORD=x", // cloud/db creds
	}
	out := scrubSensitiveEnv(in)
	kept := map[string]bool{}
	for _, kv := range out {
		kept[kv] = true
		for _, frag := range []string{"SYNAPSE_", "TOKEN", "SECRET", "ACCESS_KEY", "PASSWORD"} {
			if strings.Contains(strings.ToUpper(kv), frag) {
				t.Errorf("sensitive var must be scrubbed; found %q", kv)
			}
		}
	}
	if !kept["PATH=/usr/bin"] || !kept["HOME=/h"] || len(out) != 2 {
		t.Errorf("only the 2 non-sensitive vars must remain, got %v", out)
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
