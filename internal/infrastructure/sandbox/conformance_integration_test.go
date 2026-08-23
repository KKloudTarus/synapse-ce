//go:build linux

package sandbox_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestSandboxConformanceRunnerLive uses the production Runner.Run path to prove a scoped
// writable bind does not expose an unrelated host path. It follows the skippable Linux
// integration convention so development and Windows CI do not require sandbox support.
func TestSandboxConformanceRunnerLive(t *testing.T) {
	for _, binary := range []string{"bwrap", "bash"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skipf("%s not installed", binary)
		}
	}
	runner, err := sandbox.NewRunner(30*time.Second, 1<<20, 256<<20, 128)
	if err != nil {
		t.Skipf("sandbox unavailable: %v", err)
	}
	work := t.TempDir()
	hiddenDir := t.TempDir()
	hidden := filepath.Join(hiddenDir, "not-bound")
	if err := os.WriteFile(hidden, []byte("host-only"), 0o600); err != nil {
		t.Fatal(err)
	}
	probe := `
set -e
printf ok > "$1/writable"
test ! -e "$2"
! touch /etc/synapse-conformance-write 2>/dev/null
printf PASS
`
	res, err := runner.Run(context.Background(), ports.ToolSpec{
		Name: "bash", Args: []string{"-c", probe, "check", work, hidden}, Workdir: work,
	})
	if err != nil {
		t.Fatalf("run conformance filesystem probe: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(string(res.Stdout), "PASS") {
		t.Fatalf("filesystem conformance probe failed: exit=%d stdout=%q", res.ExitCode, res.Stdout)
	}
	if _, err := os.Stat(filepath.Join(work, "writable")); err != nil {
		t.Fatalf("declared workdir not writable: %v", err)
	}
}
