package toolrunner

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func skipIfMissing(t *testing.T, bin string) {
	t.Helper()
	if _, err := exec.LookPath(bin); err != nil {
		t.Skipf("%s not on PATH", bin)
	}
}

func TestRunArgvCapturesStdout(t *testing.T) {
	skipIfMissing(t, "echo")
	res, err := NewExecRunner(time.Second, 1<<20).Run(context.Background(),
		ports.ToolSpec{Name: "echo", Args: []string{"hello", "world"}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "hello world" {
		t.Errorf("stdout = %q, want %q", got, "hello world")
	}
	if res.ExitCode != 0 || res.TimedOut || res.Truncated {
		t.Errorf("unexpected result %+v", res)
	}
}

func TestRunTimeoutKillsProcess(t *testing.T) {
	skipIfMissing(t, "sleep")
	start := time.Now()
	res, err := NewExecRunner(50*time.Millisecond, 1<<20).Run(context.Background(),
		ports.ToolSpec{Name: "sleep", Args: []string{"10"}})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if !res.TimedOut {
		t.Error("TimedOut should be set")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("process was not killed promptly (took %s)", elapsed)
	}
}

func TestRunOutputCapTruncates(t *testing.T) {
	skipIfMissing(t, "head")
	res, err := NewExecRunner(5*time.Second, 1000).Run(context.Background(),
		ports.ToolSpec{Name: "head", Args: []string{"-c", "1000000", "/dev/zero"}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.Truncated {
		t.Error("expected Truncated to be set")
	}
	if len(res.Stdout) > 1000 {
		t.Errorf("stdout exceeded the cap: %d bytes", len(res.Stdout))
	}
}

func TestRunStdinIsData(t *testing.T) {
	skipIfMissing(t, "cat")
	res, err := NewExecRunner(5*time.Second, 1<<20).Run(context.Background(),
		ports.ToolSpec{Name: "cat", Stdin: []byte("piped-in")})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if string(res.Stdout) != "piped-in" {
		t.Errorf("stdout = %q", res.Stdout)
	}
}

func TestRunNonZeroExitIsNotAnError(t *testing.T) {
	skipIfMissing(t, "false")
	res, err := NewExecRunner(time.Second, 1<<20).Run(context.Background(),
		ports.ToolSpec{Name: "false"})
	if err != nil {
		t.Fatalf("a non-zero exit must not be a Go error: %v", err)
	}
	if res.ExitCode == 0 {
		t.Error("expected a non-zero exit code")
	}
}

func TestRunMissingBinaryErrors(t *testing.T) {
	called := false
	_, err := NewExecRunner(time.Second, 1<<20).Run(context.Background(), ports.ToolSpec{
		Name: "synapse-no-such-binary-xyz",
		Started: func(context.Context) error {
			called = true
			return nil
		},
	})
	if err == nil {
		t.Fatal("expected an error for a missing binary")
	}
	if called {
		t.Fatal("Started must not run when the child fails to start")
	}
}

func TestRunStartedCallbackAfterChildStarts(t *testing.T) {
	skipIfMissing(t, "cat")
	called := false
	res, err := NewExecRunner(time.Second, 1<<20).Run(context.Background(), ports.ToolSpec{
		Name: "cat",
		Started: func(context.Context) error {
			called = true
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !called || res.ExitCode != 0 {
		t.Fatalf("callback called=%v result=%+v", called, res)
	}
}

func TestRunStartedFailureKillsChild(t *testing.T) {
	skipIfMissing(t, "sleep")
	want := errors.New("setup failed")
	start := time.Now()
	_, err := NewExecRunner(10*time.Second, 1<<20).Run(context.Background(), ports.ToolSpec{
		Name: "sleep",
		Args: []string{"10"},
		Started: func(context.Context) error {
			return want
		},
	})
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want callback failure", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("callback failure did not kill child promptly: %s", elapsed)
	}
}

func TestRunTimeoutDuringStartedCallbackFailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-group termination assertion is Unix-only")
	}
	skipIfMissing(t, "sleep")
	res, err := NewExecRunner(50*time.Millisecond, 1<<20).Run(context.Background(), ports.ToolSpec{
		Name: "sleep",
		Args: []string{"10"},
		Started: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
	})
	if err == nil || !res.TimedOut {
		t.Fatalf("result=%+v error=%v, want timeout", res, err)
	}
}

// A process that dies during the initialization step makes that step fail for a reason describing
// its own symptom. A recon run reported `Bind /proc/33852/ns/net failed: No such file or directory`,
// which says the sandbox pid had vanished and nothing about why; the cause was the one line the
// sandbox had written to stderr before dying. The error must carry it.
func TestRunStartedFailureReportsWhatTheToolWrote(t *testing.T) {
	skipIfMissing(t, "sh")
	res, err := NewExecRunner(10*time.Second, 1<<20).Run(context.Background(), ports.ToolSpec{
		Name: "sh",
		Args: []string{"-c", "echo 'bwrap: Cannot find source path /x: Permission denied' >&2; sleep 10"},
		Started: func(context.Context) error {
			// The step the tool's own failure breaks, reported as its symptom.
			time.Sleep(200 * time.Millisecond)
			return errors.New("egress netns setup: no such process")
		},
	})
	if err == nil {
		t.Fatal("want an initialization error")
	}
	if !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("error = %q, want it to carry the line the tool wrote to stderr", err)
	}
	if !strings.Contains(err.Error(), "egress netns setup") {
		t.Fatalf("error = %q, want it to keep the failing step", err)
	}
	if !bytes.Contains(res.Stderr, []byte("Permission denied")) {
		t.Errorf("stderr must still be returned in full, got %q", res.Stderr)
	}
}

func TestFirstLineSkipsBlanksAndBoundsLength(t *testing.T) {
	if got := firstLine([]byte("\n\n  real cause  \nnoise\n")); got != "real cause" {
		t.Errorf("firstLine = %q, want the first non-empty line trimmed", got)
	}
	if got := firstLine(nil); got != "" {
		t.Errorf("firstLine(nil) = %q, want empty", got)
	}
	long := firstLine([]byte(strings.Repeat("x", 500)))
	if len([]rune(long)) != 241 {
		t.Errorf("firstLine length = %d runes, want 240 plus the ellipsis", len([]rune(long)))
	}
}
