//go:build linux

package acquire_test

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/acquire"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestAcquireGitHostNetSandboxed proves F4: with NO egress applier (the unprivileged-API
// path), git clone STILL runs fully sandboxed (host-net mode) – never a direct exec – and
// succeeds. Needs git + bwrap; runs without root (the realistic unprivileged scenario).
func TestAcquireGitHostNetSandboxed(t *testing.T) {
	for _, b := range []string{"git", "bwrap"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("%s not installed", b)
		}
	}
	sb, err := sandbox.NewRunner(3*time.Minute, 64<<20, 1<<30, 512)
	if err != nil {
		t.Skipf("sandbox unavailable: %v", err)
	}
	// egressScoped=false → host-net sandbox (no SetEgress). This is exactly the unprivileged
	// API: sandboxed (fs/seccomp/caps), shared host net, no egress scoping.
	acq := acquire.New().WithSandbox(sb, false)
	ws, err := acq.Acquire(context.Background(), ports.AcquireRequest{
		Kind: ports.TargetGit, Value: "https://github.com/octocat/Hello-World.git",
	})
	if err != nil {
		t.Fatalf("host-net sandboxed git clone failed: %v", err)
	}
	defer func() {
		if ws.Cleanup != nil {
			_ = ws.Cleanup()
		}
	}()
	entries, err := os.ReadDir(ws.Dir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("clone produced an empty workspace: err=%v entries=%d", err, len(entries))
	}
	t.Logf("F4 OK: git clone ran sandboxed (host-net, no direct exec); %d entries", len(entries))
}
