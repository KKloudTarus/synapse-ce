//go:build linux

package responseactuator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

func TestRegistrySignalsOnlyPinnedObservedProcess(t *testing.T) {
	command := exec.Command("/bin/sleep", "30")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill() }()
	startTick, err := readProcessStartTick(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	registry := &Registry{entries: make(map[shared.ID]*trackedProcess)}
	defer func() { _ = registry.Close() }()
	event := detection.ProcessEvent{
		Kind: "exec", PID: command.Process.Pid, PPID: 1, StartTimeNanos: startTick * linuxUserTickNanos,
		Comm: "sleep", Path: "/bin/sleep",
	}
	registry.ObserveProcess("asset-1", "boot-1", event)
	entityID := telemetry.ProcessEntityID("asset-1", "boot-1", event.PID, event.StartTimeNanos)
	already, err := registry.StopProcess(context.Background(), entityID)
	if err != nil || already {
		t.Fatalf("stop pinned process: already=%v err=%v", already, err)
	}
	already, err = registry.StopProcess(context.Background(), entityID)
	if err != nil || !already {
		t.Fatalf("duplicate stop must be locally idempotent: already=%v err=%v", already, err)
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("pinned process did not receive SIGTERM")
	}
	event.Kind = "exit"
	registry.ObserveProcess("asset-1", "boot-1", event)
	already, err = registry.StopProcess(context.Background(), entityID)
	if err != nil || !already {
		t.Fatalf("observed process exit was not idempotent: already=%v err=%v", already, err)
	}
}

func TestRegistryStopHonorsCancellationWhileWaitingForLock(t *testing.T) {
	registry := &Registry{entries: make(map[shared.ID]*trackedProcess)}
	registry.mu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := registry.StopProcess(ctx, "process-1")
		done <- err
	}()
	cancel()
	registry.mu.Unlock()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("stop after cancellation error = %v, want context.Canceled", err)
	}
}

func TestRegistryRestartFailsClosedWithoutPinnedExecutableDescriptor(t *testing.T) {
	registry := &Registry{entries: make(map[shared.ID]*trackedProcess)}
	_, err := registry.RestartProcess(context.Background(), "process-1")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("restart error = %v, want not found", err)
	}
}

func TestRegistryRestartDescriptorPinnedHarmlessProcess(t *testing.T) {
	requireRoot(t)
	binary := buildRestartProbe(t)
	workDir := restartWorkDir(t)
	out := filepath.Join(workDir, "restarted")
	command := restartProbeCommand(t, binary, workDir)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill() }()

	registry, entityID := observeRestartableProcess(t, command.Process.Pid)
	defer func() { _ = registry.Close() }()
	if process := registry.entries[entityID]; process.executable == nil || process.workingDir == nil {
		t.Fatal("eligible process did not retain descriptor-pinned restart identity")
	}
	already, err := registry.StopProcess(context.Background(), entityID)
	if err != nil || already {
		t.Fatalf("stop process: already=%v err=%v", already, err)
	}
	waitForExit(t, command, 5*time.Second)
	permitProbeRestart(t, workDir)
	already, err = registry.RestartProcess(context.Background(), entityID)
	if err != nil || already {
		t.Fatalf("restart process: already=%v err=%v", already, err)
	}
	if err := validateRestartableProcess(registry.entries[entityID]); err != nil {
		t.Fatalf("successful restart consumed registry-owned descriptors: %v", err)
	}
	waitForFile(t, out, 5*time.Second)
	already, err = registry.RestartProcess(context.Background(), entityID)
	if err != nil || !already {
		t.Fatalf("duplicate restart: already=%v err=%v", already, err)
	}
}

func TestRegistryRestartResistsExecutablePathReplacement(t *testing.T) {
	requireRoot(t)
	binary := buildRestartProbe(t)
	workDir := restartWorkDir(t)
	out := filepath.Join(workDir, "restarted")
	command := restartProbeCommand(t, binary, workDir)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill() }()
	registry, entityID := observeRestartableProcess(t, command.Process.Pid)
	defer func() { _ = registry.Close() }()

	// Rename a hostile replacement over the original path after descriptor capture. Restart must still
	// execute the pinned inode, proven by the expected probe output rather than the replacement marker.
	replacement := binary + ".replacement"
	if err := os.WriteFile(replacement, []byte("#!/bin/sh\necho replaced > replaced\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(replacement, restartTestUIDGID, restartTestUIDGID); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Rename(replacement, binary); err != nil {
		t.Fatal(err)
	}
	already, err := registry.StopProcess(context.Background(), entityID)
	if err != nil || already {
		t.Fatalf("stop process: already=%v err=%v", already, err)
	}
	waitForExit(t, command, 5*time.Second)
	permitProbeRestart(t, workDir)
	if _, err := registry.RestartProcess(context.Background(), entityID); err != nil {
		t.Fatalf("restart process after path replacement: %v", err)
	}
	waitForFile(t, out, 5*time.Second)
	if _, err := os.Stat(filepath.Join(workDir, "replaced")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restart used mutable executable path: replaced marker error=%v", err)
	}
}

func TestRegistryRestartRejectsUnsafeIdentityAndArguments(t *testing.T) {
	if os.Geteuid() != 0 {
		binary := buildRestartProbe(t)
		command := exec.Command(binary, "unsafe-argument")
		command.Env = []string{"SECRET_TEST_VALUE=not-retained"}
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = command.Process.Kill() }()
		startTick, err := readProcessStartTick(command.Process.Pid)
		if err != nil {
			t.Fatal(err)
		}
		process, err := pinProcess("process-1", command.Process.Pid, startTick*linuxUserTickNanos, true)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = process.close() }()
		if process.executable != nil || process.workingDir != nil {
			t.Fatal("argument-bearing process must not retain restart material")
		}
	}
	if err := validateLaunchIdentity(launchSpec{uid: 0, gid: 1}); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("root user identity error = %v, want forbidden", err)
	}
	if err := validateLaunchIdentity(launchSpec{uid: 1, gid: 0}); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("root group identity error = %v, want forbidden", err)
	}
}

func TestRegistryRestartHonorsCancellationAndClosesDescriptors(t *testing.T) {
	requireRoot(t)
	binary := buildRestartProbe(t)
	command := restartProbeCommand(t, binary, restartWorkDir(t))
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill() }()
	registry, entityID := observeRestartableProcess(t, command.Process.Pid)
	process := registry.entries[entityID]
	if process.executable == nil || process.workingDir == nil {
		t.Fatal("eligible process did not retain restart descriptors")
	}
	pidfd, executableFD, workingDirFD := process.pidfd, process.executable.fd, process.workingDir.fd
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := registry.RestartProcess(ctx, entityID); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled restart error = %v, want context.Canceled", err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	for _, fd := range []int{pidfd, executableFD, workingDirFD} {
		if _, err := fileIdentityForFD(fd); err == nil {
			t.Fatalf("descriptor %d remained open after registry close", fd)
		}
	}
}

func observeRestartableProcess(t *testing.T, pid int) (*Registry, shared.ID) {
	t.Helper()
	startTick, err := readProcessStartTick(pid)
	if err != nil {
		t.Fatal(err)
	}
	registry := &Registry{entries: make(map[shared.ID]*trackedProcess)}
	event := detection.ProcessEvent{Kind: "exec", PID: pid, PPID: os.Getpid(), StartTimeNanos: startTick * linuxUserTickNanos}
	registry.ObserveProcess("asset-1", "boot-1", event)
	entityID := telemetry.ProcessEntityID("asset-1", "boot-1", event.PID, event.StartTimeNanos)
	if registry.entries[entityID] == nil {
		_ = registry.Close()
		t.Fatal("registry did not pin observed process")
	}
	return registry, entityID
}

const restartTestUIDGID = 65534

func restartProbeCommand(t *testing.T, binary, workDir string) *exec.Cmd {
	t.Helper()
	command := exec.Command(binary)
	command.Dir = workDir
	command.Env = []string{}
	if os.Geteuid() == 0 {
		command.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: restartTestUIDGID, Gid: restartTestUIDGID},
		}
	}
	return command
}

func restartWorkDir(t *testing.T) string {
	t.Helper()
	return restartTempDir(t, "synapse-restart-work-*")
}

func restartTempDir(t *testing.T, pattern string) string {
	t.Helper()
	// testing.T.TempDir nests paths below a test-owned 0700 parent. A deliberately non-root probe could
	// not traverse that parent, so create the owner-only test directory directly below the system temp dir.
	dir, err := os.MkdirTemp("", pattern)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(dir, restartTestUIDGID, restartTestUIDGID); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func permitProbeRestart(t *testing.T, workDir string) {
	t.Helper()
	path := filepath.Join(workDir, "stop")
	if err := os.WriteFile(path, []byte("restart"), 0o600); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, restartTestUIDGID, restartTestUIDGID); err != nil {
			t.Fatal(err)
		}
	}
}

func buildRestartProbe(t *testing.T) string {
	t.Helper()
	dir := restartTempDir(t, "synapse-restart-probe-*")
	source := filepath.Join(dir, "probe.go")
	binary := filepath.Join(dir, "probe")
	program := `package main
import (
 "os"
 "path/filepath"
 "time"
)
func main() {
 if _, err := os.Stat("restarted"); err == nil { os.Exit(0) }
 for { if _, err := os.Stat("stop"); err == nil { _ = os.WriteFile(filepath.Join(".", "restarted"), []byte("pinned"), 0600); return }; time.Sleep(10*time.Millisecond) }
}`
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", binary, source)
	build.Env = append([]string{}, os.Environ()...)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build probe: %v: %s", err, output)
	}
	if err := os.Chmod(binary, 0o700); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(binary, restartTestUIDGID, restartTestUIDGID); err != nil {
			t.Fatal(err)
		}
	}
	return binary
}

func waitForExit(t *testing.T, command *exec.Cmd, timeout time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if err != nil && !strings.Contains(err.Error(), "signal: terminated") {
			t.Fatalf("wait stopped process: %v", err)
		}
	case <-time.After(timeout):
		t.Fatal("process did not exit")
	}
}

func waitForFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil {
			if string(data) != "pinned" {
				t.Fatalf("restart output = %q, want pinned", data)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("restart did not create %s", path)
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip(fmt.Sprintf("descriptor-pinned restart needs root; uid=%d", os.Geteuid()))
	}
}
