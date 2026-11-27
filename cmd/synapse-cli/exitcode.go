package main

import (
	"errors"
	"fmt"
	"os"
)

// Exit codes are a CI contract (docs/guide/cli.md, Exit codes). A pipeline branches on them, so a gate
// result and a scanner that could not finish must not share a code: before #1665 both were 1, and the
// only way to tell "findings over threshold" from "the scan broke" was to parse the output.
const (
	exitGate    = 1 // the command ran and a gate it was asked to apply failed
	exitUsage   = 2 // invalid invocation; nothing was analyzed
	exitRuntime = 3 // the command could not complete
)

// gateFailure is an error that reports a gate result rather than a failure to run.
type gateFailure struct{ msg string }

func (g gateFailure) Error() string { return g.msg }

// gateFailed builds the error a command returns when a gate it applied did not pass.
func gateFailed(format string, args ...any) error {
	return gateFailure{msg: fmt.Sprintf(format, args...)}
}

// usageError is an error that reports an invalid invocation: nothing was analyzed.
type usageError struct{ msg string }

func (u usageError) Error() string { return u.msg }

// usageFailed builds the error a subcommand returns for an option it cannot accept.
func usageFailed(format string, args ...any) error {
	return usageError{msg: fmt.Sprintf(format, args...)}
}

// exitCodeFor maps a command's error to its exit code: a gate result anywhere in the chain is
// exitGate, an invalid invocation exitUsage, anything else exitRuntime.
func exitCodeFor(err error) int {
	var gate gateFailure
	if errors.As(err, &gate) {
		return exitGate
	}
	var usage usageError
	if errors.As(err, &usage) {
		return exitUsage
	}
	return exitRuntime
}

// fail reports err and exits with the code its kind carries.
func fail(err error) {
	fmt.Fprintln(os.Stderr, "synapse-cli:", err)
	os.Exit(exitCodeFor(err))
}

// stdoutOwners counts the output modes that write their document to stdout. --sarif-out writes a file,
// so SARIF counts only when it has no path.
func stdoutOwners(jsonOut, sbomOut, sarifOut bool, sarifPath string) int {
	n := 0
	for _, on := range []bool{jsonOut, sbomOut, sarifOut && sarifPath == ""} {
		if on {
			n++
		}
	}
	return n
}
