//go:build unix

package toolrunner

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestRunTimeoutKillsProcessGroup is the regression test for F-1: a tool that spawns
// a background child must NOT leave that child alive after the runner's timeout. We
// exec `sh` (as a binary – argv only, no shell string is built from input) which forks
// a long `sleep`, records its pid, then blocks; on timeout the runner must kill the
// whole process group, taking the orphaned sleep with it.
func TestRunTimeoutKillsProcessGroup(t *testing.T) {
	skipIfMissing(t, "sh")
	skipIfMissing(t, "sleep")

	pidFile := filepath.Join(t.TempDir(), "child.pid")
	// Background a long sleep, write its pid, then wait – so the script outlives the
	// short timeout and the sleep is a grandchild of the runner.
	script := "sleep 30 & echo $! > " + pidFile + "; wait"

	res, err := NewExecRunner(300*time.Millisecond, 1<<20).Run(context.Background(),
		ports.ToolSpec{Name: "sh", Args: []string{"-c", script}})
	if err == nil || !res.TimedOut {
		t.Fatalf("expected a timeout, got err=%v timedOut=%v", err, res.TimedOut)
	}

	pid := readPID(t, pidFile)
	// After a group kill the grandchild dies; poll briefly to avoid a reap race.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !alive(pid) {
			return // success: the grandchild was killed with the group
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Clean up the orphan we just proved leaked, so the test host isn't littered.
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatalf("grandchild pid %d survived the timeout – process group was not killed (F-1)", pid)
}

func readPID(t *testing.T, path string) int {
	t.Helper()
	var data []byte
	// The child writes the pid file asynchronously; give it a moment.
	for i := 0; i < 50; i++ {
		if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) > 0 {
			data = b
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		t.Fatalf("could not read child pid from %s: %q (%v)", path, data, err)
	}
	return pid
}

// alive reports whether pid exists (signal 0 probes without killing).
func alive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}
