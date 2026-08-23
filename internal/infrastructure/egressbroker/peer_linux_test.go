//go:build linux

package egressbroker

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSandboxProcessAliveUsesPidfdReadiness(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	waited := false
	defer func() {
		if waited {
			return
		}
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	pidfd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if errors.Is(err, unix.ENOSYS) {
		t.Skip("pidfd_open is unavailable on this kernel")
	}
	if err != nil {
		t.Fatalf("open pidfd: %v", err)
	}
	process := &sandboxProcess{pidfd: pidfd, netnsFD: -1}
	defer func() {
		if err := process.Close(); err != nil {
			t.Errorf("close sandbox process: %v", err)
		}
	}()

	if err := process.Alive(); err != nil {
		t.Fatalf("live process reported dead: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill child: %v", err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("killed child exited successfully")
	}
	waited = true

	if err := process.Alive(); err == nil || !strings.Contains(err.Error(), "exited") {
		t.Fatalf("exited process result = %v, want exited error", err)
	}
}

func TestSandboxProcessAliveRejectsClosedIdentity(t *testing.T) {
	process := &sandboxProcess{pidfd: -1, netnsFD: -1}
	if err := process.Alive(); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed process result = %v, want closed error", err)
	}
}

func TestRequireBubblewrapPipesAcceptsClosedStatusAfterChildPID(t *testing.T) {
	blockReader, blockWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create block pipe: %v", err)
	}
	defer blockReader.Close()
	defer blockWriter.Close()
	statusReader, statusWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create status pipe: %v", err)
	}
	statusFD := int(statusReader.Fd())
	if err := statusReader.Close(); err != nil {
		t.Fatalf("close published status descriptor: %v", err)
	}
	defer statusWriter.Close()

	if err := requireBubblewrapPipes(os.Getpid(), int(blockReader.Fd()), statusFD); err != nil {
		t.Fatalf("closed status descriptor rejected: %v", err)
	}
}

func TestRequireBubblewrapPipesAcceptsOpenStatusPipe(t *testing.T) {
	blockReader, blockWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create block pipe: %v", err)
	}
	defer blockReader.Close()
	defer blockWriter.Close()
	statusReader, statusWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create status pipe: %v", err)
	}
	defer statusReader.Close()
	defer statusWriter.Close()

	if err := requireBubblewrapPipes(os.Getpid(), int(blockReader.Fd()), int(statusReader.Fd())); err != nil {
		t.Fatalf("open status pipe rejected: %v", err)
	}
}

func TestRequireBubblewrapPipesRejectsMissingBlockPipe(t *testing.T) {
	blockReader, blockWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create block pipe: %v", err)
	}
	blockFD := int(blockReader.Fd())
	if err := blockReader.Close(); err != nil {
		t.Fatalf("close block descriptor: %v", err)
	}
	defer blockWriter.Close()

	if err := requireBubblewrapPipes(os.Getpid(), blockFD, blockFD+1024); err == nil || !strings.Contains(err.Error(), "block fd") {
		t.Fatalf("missing block descriptor result = %v, want block fd error", err)
	}
}

func TestRequireBubblewrapPipesRejectsNonPipeDescriptor(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "not-a-pipe-")
	if err != nil {
		t.Fatalf("create regular file: %v", err)
	}
	defer file.Close()
	statusReader, statusWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create status pipe: %v", err)
	}
	defer statusReader.Close()
	defer statusWriter.Close()

	if err := requireBubblewrapPipes(os.Getpid(), int(file.Fd()), int(statusReader.Fd())); err == nil || !strings.Contains(err.Error(), "not a pipe") {
		t.Fatalf("regular block descriptor result = %v, want not-a-pipe error", err)
	}
}
