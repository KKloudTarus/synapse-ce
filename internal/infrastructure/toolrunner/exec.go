// Package toolrunner runs argv-based tools for the recon use case. It is the single
// execution primitive behind the ToolRunner port: a command is always invoked as an
// argv array via os/exec – NEVER a shell string – with a per-run
// timeout (the WHOLE process group is killed on deadline, so resolver/helper
// grandchildren cannot outlive the authorization window) and a hard output-size cap
// . It performs no scope/authorization logic itself; the caller must have
// passed the execution guard first.
package toolrunner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Sensible defaults if a ToolSpec leaves them zero.
const (
	defaultTimeout = 2 * time.Minute
	defaultMaxOut  = 8 << 20 // 8 MiB per stream
	// waitDelay bounds how long Wait blocks after the process is signalled before
	// os/exec force-closes the output pipes – so a grandchild that inherited a pipe
	// cannot hang the runner indefinitely after a timeout/kill.
	waitDelay = 3 * time.Second
)

// ExecRunner implements ports.ToolRunner using os/exec.
type ExecRunner struct {
	timeout time.Duration
	maxOut  int
}

var _ ports.ToolRunner = (*ExecRunner)(nil)

// NewExecRunner returns a runner with the given default timeout and per-stream
// output cap; non-positive values fall back to the package defaults.
func NewExecRunner(timeout time.Duration, maxOut int) *ExecRunner {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if maxOut <= 0 {
		maxOut = defaultMaxOut
	}
	return &ExecRunner{timeout: timeout, maxOut: maxOut}
}

// Run executes spec as an argv array, bounded by timeout + output cap. A non-zero
// exit is reported via ToolResult.ExitCode (not a Go error) so the caller still
// gets partial output; a missing binary, a timeout, or a cancelled context returns
// an error alongside whatever output was captured.
func (r *ExecRunner) Run(ctx context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	if spec.Name == "" {
		return ports.ToolResult{}, fmt.Errorf("%w: toolrunner empty command name", shared.ErrValidation)
	}
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = r.timeout
	}
	maxOut := spec.MaxOutputBytes
	if maxOut <= 0 {
		maxOut = r.maxOut
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// argv only: the binary is arg 0 and never interpolated into a shell.
	cmd := exec.CommandContext(runCtx, spec.Name, spec.Args...)
	if len(spec.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(spec.Stdin)
	}
	// A non-nil Env sets the child environment exactly (nil = inherit the parent's, the
	// default). The SandboxRunner uses this to hand bwrap a controlled env carrying any
	// resolved secrets, so they reach the tool via the environment, not argv.
	if spec.Env != nil {
		cmd.Env = spec.Env
	}
	// Put the tool in its own process group and, on context cancel/timeout, kill the
	// WHOLE group – recon tools (subfinder/httpx/naabu) spawn resolver/helper children
	// that the default single-child kill would orphan past the timeout and the
	// authorization window (F-1). WaitDelay caps any post-kill pipe-drain hang.
	configureProcessGroup(cmd)
	placeInCgroup(cmd, spec.CgroupFD) // clone into the connect-logger's cgroup (Linux)
	cmd.ExtraFiles = spec.ExtraFiles  // F1: inherited at fd 3+ (bwrap's --seccomp fd)
	cmd.WaitDelay = waitDelay
	outW := &capWriter{limit: maxOut}
	errW := &capWriter{limit: maxOut}
	cmd.Stdout = outW
	cmd.Stderr = errW

	runErr := cmd.Run()
	res := ports.ToolResult{
		Stdout:    outW.buf.Bytes(),
		Stderr:    errW.buf.Bytes(),
		Truncated: outW.truncated || errW.truncated,
	}

	if runCtx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		return res, fmt.Errorf("toolrunner: %q exceeded its %s timeout", spec.Name, timeout)
	}
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			// Ran to completion but exited non-zero – surface the code, not an error.
			res.ExitCode = ee.ExitCode()
			return res, nil
		}
		// Binary not found / not executable / parent context cancelled, etc.
		return res, fmt.Errorf("toolrunner: run %q: %w", spec.Name, runErr)
	}
	return res, nil
}

// capWriter buffers output up to limit bytes, then silently drops the rest and
// records that truncation happened. It always reports a full write so the child
// process never sees a short-write error when its output is capped.
type capWriter struct {
	limit     int
	buf       bytes.Buffer
	truncated bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	remaining := w.limit - w.buf.Len()
	if remaining <= 0 {
		w.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		w.buf.Write(p[:remaining])
		w.truncated = true
		return len(p), nil
	}
	w.buf.Write(p)
	return len(p), nil
}
