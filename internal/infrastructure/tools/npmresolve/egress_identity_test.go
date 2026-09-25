package npmresolve

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// captureRunner records the spec it was handed and returns a clean result.
type captureRunner struct{ spec ports.ToolSpec }

func (c *captureRunner) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	c.spec = spec
	return ports.ToolResult{ExitCode: 0}, nil
}

// A sandboxed resolver reaches a registry, so its spec carries an egress policy, and the sandbox
// refuses a policy without an authoritative execution identity. The resolver had none, so it failed
// for that reason on every scan with the sandbox enabled, and a project with a manifest but no
// lockfile resolved to nothing while the scan called it "no recognized dependency manifests".
func TestResolvePassesTheEgressExecutionIdentityFromContext(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"x","version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &captureRunner{}
	resolver := New("npm").WithRunner(runner)

	ctx := ports.WithEgressExecution(context.Background(), "sca", "evidence-42")
	_, _ = resolver.Resolve(ctx, dir)

	if runner.spec.EgressPolicy == nil {
		t.Fatal("the spec carries no egress policy, so the resolver never reached the registry path")
	}
	if runner.spec.EgressExecutionKind != "sca" || runner.spec.EgressExecutionID != "evidence-42" {
		t.Fatalf("execution identity = %q/%q, want the one bound to the context",
			runner.spec.EgressExecutionKind, runner.spec.EgressExecutionID)
	}
}

// Without an identity the fields stay empty so the sandbox refuses the run. Inventing one here
// would let a tool reach a registry under an authorization that ties back to no record.
func TestResolveLeavesTheIdentityEmptyWhenTheContextCarriesNone(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"x","version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &captureRunner{}
	_, _ = New("npm").WithRunner(runner).Resolve(context.Background(), dir)

	if runner.spec.EgressExecutionKind != "" || runner.spec.EgressExecutionID != "" {
		t.Fatalf("execution identity = %q/%q, want empty so the sandbox fails closed",
			runner.spec.EgressExecutionKind, runner.spec.EgressExecutionID)
	}
}
