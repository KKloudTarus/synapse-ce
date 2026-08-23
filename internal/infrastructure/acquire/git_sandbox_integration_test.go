package acquire_test

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/acquire"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/egress"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestAcquireGitSandboxedEgress proves E15: `git clone` runs inside the sandbox with
// egress restricted to the repo host, and still clones a real public repo. Needs git +
// bubblewrap + CAP_NET_ADMIN (run the binary with sudo on the host).
type authoritativeTestRunner struct {
	ports.ToolRunner
}

func (r authoritativeTestRunner) Run(ctx context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	spec.EgressExecutionKind = "recon"
	spec.EgressExecutionID = "acquisition-integration"
	return r.ToolRunner.Run(ctx, spec)
}

func TestAcquireGitSandboxedEgress(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bubblewrap not installed")
	}
	sb, err := sandbox.NewRunner(3*time.Minute, 64<<20, 1<<30, 512)
	if err != nil {
		t.Skipf("sandbox unavailable: %v", err)
	}
	app, err := egress.NewApplier()
	if err != nil {
		t.Skipf("egress applier unavailable: %v", err)
	}
	ctx := context.Background()
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	perr := app.Probe(pctx)
	cancel()
	if perr != nil {
		t.Skipf("egress not usable (run with sudo for CAP_NET_ADMIN): %v", perr)
	}
	sb.SetEgress(app)

	acq := acquire.New().WithSandbox(authoritativeTestRunner{ToolRunner: sb}, true)
	ws, err := acq.Acquire(ctx, ports.AcquireRequest{Kind: ports.TargetGit, Value: "https://github.com/octocat/Hello-World.git"})
	if err != nil {
		t.Fatalf("sandboxed git clone failed: %v", err)
	}
	defer func() {
		if ws.Cleanup != nil {
			_ = ws.Cleanup()
		}
	}()
	entries, err := os.ReadDir(ws.Dir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("cloned workspace is empty (egress blocked the clone?): err=%v entries=%d", err, len(entries))
	}
	t.Logf("sandboxed clone OK: %d entries in %s", len(entries), ws.Dir)
}
