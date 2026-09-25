//go:build linux

package sandbox_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sandbox"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// A shell inside the sandbox must be able to run an external command.
//
// The seccomp allowlist omitted vfork while the clone filter allowed the identical
// CLONE_VM|CLONE_VFORK|SIGCHLD, so glibc's vfork(), which issues the syscall directly rather than
// routing through clone, was denied with EPERM. dash uses vfork to spawn a simple command and
// fork for a pipeline, which is why "/bin/true" failed with "Cannot fork" while "echo x | cat"
// succeeded: the sandbox could run a pipeline but not a plain external program, so any tool that
// shells out was broken.
//
// This needs a kernel that lets bubblewrap create namespaces; it skips where it cannot.
func TestSandboxRunsExternalCommandFromShell(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not installed")
	}
	sb, err := sandbox.NewRunner(30*time.Second, 8<<20, 1<<30, 256)
	if err != nil {
		t.Skipf("sandbox unavailable: %v", err)
	}

	for _, tc := range []struct {
		name   string
		script string
		want   string
	}{
		// The simple-command path, which uses vfork.
		{"simple external command", "/bin/echo EXTERNAL_OK", "EXTERNAL_OK"},
		// The pipeline path, which uses fork. It worked before the fix and must keep working.
		{"external command in a pipeline", "echo PIPE_OK | cat", "PIPE_OK"},
		// A command found on PATH rather than by absolute path.
		{"command resolved on PATH", "echo PATH_OK | cat -", "PATH_OK"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := sb.Run(context.Background(), ports.ToolSpec{Name: "sh", Args: []string{"-c", tc.script}})
			if err != nil {
				t.Fatalf("run: %v (stderr %q)", err, res.Stderr)
			}
			if strings.Contains(string(res.Stderr), "Cannot fork") {
				t.Fatalf("shell could not spawn the command: stderr=%q", res.Stderr)
			}
			if !strings.Contains(string(res.Stdout), tc.want) {
				t.Fatalf("stdout=%q stderr=%q, want %q", res.Stdout, res.Stderr, tc.want)
			}
		})
	}
}
