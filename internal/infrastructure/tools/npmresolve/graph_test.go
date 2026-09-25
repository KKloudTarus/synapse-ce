package npmresolve

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// lockWritingRunner stands in for npm: it writes the lockfile npm would have produced into the
// throwaway workdir the resolver prepared.
type lockWritingRunner struct{ lock string }

func (r *lockWritingRunner) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	if err := os.WriteFile(filepath.Join(spec.Workdir, "package-lock.json"), []byte(r.lock), 0o600); err != nil {
		return ports.ToolResult{}, err
	}
	return ports.ToolResult{ExitCode: 0}, nil
}

// The generated lockfile carries the dependency tree, and the resolver used to discard it. Without the
// edges the SCA pipeline cannot tell a direct dependency from a transitive one, cannot show the path
// from the project root to a vulnerable package, and cannot compute a remediation plan: every CVE in a
// lockfile-less npm project came out with Direct=false and no path.
func TestResolveGraphReturnsTheDependencyEdges(t *testing.T) {
	const lock = `{
	  "name": "app", "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "app", "version": "1.0.0", "dependencies": {"top": "^1.0.0"}},
	    "node_modules/top": {"version": "1.0.0", "dependencies": {"deep": "^2.0.0"}},
	    "node_modules/deep": {"version": "2.0.0"}
	  }
	}`
	dir := t.TempDir()
	write(t, filepath.Join(dir, "package.json"), `{"name":"app","version":"1.0.0","dependencies":{"top":"^1.0.0"}}`)

	comps, deps, err := New("npm").WithRunner(&lockWritingRunner{lock: lock}).ResolveGraph(context.Background(), dir)
	if err != nil {
		t.Fatalf("ResolveGraph: %v", err)
	}
	if len(comps) != 2 {
		t.Fatalf("components = %d, want 2 (top, deep)", len(comps))
	}
	if len(deps) == 0 {
		t.Fatal("no dependency edges returned; a transitive CVE cannot be given a path to the root")
	}
	var found bool
	for _, d := range deps {
		if d.Ref == "pkg:npm/top@1.0.0" {
			for _, t := range d.DependsOn {
				if t == "pkg:npm/deep@2.0.0" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("want the edge top@1.0.0 -> deep@2.0.0, got %+v", deps)
	}
}

// Resolve is the components-only view of the same call, kept for ports.NPMResolver.
func TestResolveMatchesResolveGraphComponents(t *testing.T) {
	const lock = `{
	  "name": "app", "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "app", "version": "1.0.0"},
	    "node_modules/top": {"version": "1.0.0"}
	  }
	}`
	dir := t.TempDir()
	write(t, filepath.Join(dir, "package.json"), `{"name":"app","version":"1.0.0"}`)

	comps, err := New("npm").WithRunner(&lockWritingRunner{lock: lock}).Resolve(context.Background(), dir)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(comps) != 1 || comps[0].Name != "top" {
		t.Fatalf("components = %+v, want just top@1.0.0", comps)
	}
}
