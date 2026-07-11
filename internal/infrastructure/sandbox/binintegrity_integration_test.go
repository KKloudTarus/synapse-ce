//go:build linux

package sandbox_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/platform/binregistry"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestBinaryIntegrityRefusesTamper proves F5: once a tool binary is pinned (TOFU on first
// run), replacing it makes the next run be REFUSED before exec.
func TestBinaryIntegrityRefusesTamper(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not installed")
	}
	sb, err := sandbox.NewRunner(20*time.Second, 8<<20, 1<<30, 256)
	if err != nil {
		t.Skipf("sandbox unavailable: %v", err)
	}
	sb.SetBinaryRegistry(binregistry.New(nil, true))

	dir := t.TempDir()
	tool := filepath.Join(dir, "tool")
	// A tiny static-ish tool: use /bin/true's bytes copied in, or a shell script won't work
	// as an exec target under PATH resolution – copy the real `true` binary.
	src, _ := exec.LookPath("true")
	b, _ := os.ReadFile(src)
	if err := os.WriteFile(tool, b, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// First run pins the hash (TOFU) and succeeds.
	if _, err := sb.Run(ctx, ports.ToolSpec{Name: tool, Workdir: dir}); err != nil {
		t.Fatalf("first run should succeed + pin: %v", err)
	}
	// Replace the binary.
	if err := os.WriteFile(tool, append(b, '\n'), 0o755); err != nil {
		t.Fatal(err)
	}
	// Second run must be refused with an integrity error (before exec).
	_, err = sb.Run(ctx, ports.ToolSpec{Name: tool, Workdir: dir})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("a replaced binary must be REFUSED, got %v", err)
	}
	t.Logf("F5 OK: replaced binary refused before exec (%v)", err)
}
