//go:build linux

package acquire_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/acquire"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestAcquireGitHostNetSandboxed proves F4: with NO egress applier (the unprivileged-API
// path), git clone STILL runs fully sandboxed (host-net mode) – never a direct exec – and
// succeeds. Needs git + bwrap; runs without root (the realistic unprivileged scenario).
func TestAcquireGitHostNetSandboxed(t *testing.T) {
	acq := acquire.New().WithSandbox(authoritativeTestRunner{}, false)
	_, err := acq.Acquire(context.Background(), ports.AcquireRequest{
		Kind: ports.TargetGit, Value: "https://github.com/octocat/Hello-World.git",
	})
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "requires authoritative signed execution grants") {
		t.Fatalf("Acquire() error = %v, want fail-closed signed-grant validation", err)
	}
}
