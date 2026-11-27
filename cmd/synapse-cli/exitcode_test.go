package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestExitCodeSeparatesGateResultsFromRuntimeFailures(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{name: "finding gate", err: gateFailed("%d finding(s) at or above %s", 2, "high"), want: exitGate},
		{name: "gate wrapped by a caller", err: fmt.Errorf("scan: %w", gateFailed("quality gate FAILED")), want: exitGate},
		{name: "runtime failure", err: errors.New("acquire target: permission denied"), want: exitRuntime},
		{name: "wrapped runtime failure", err: fmt.Errorf("scan: %w", errors.New("sbom generator crashed")), want: exitRuntime},
		{name: "subcommand usage", err: usageFailed("unknown or incomplete option %q", "--bogus"), want: exitUsage},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exitCodeFor(tc.err); got != tc.want {
				t.Fatalf("exitCodeFor(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
	if exitGate == exitRuntime || exitUsage == exitRuntime || exitGate == exitUsage {
		t.Fatal("exit codes must be distinct")
	}
	if got := gateFailed("%d finding(s) at or above %s", 3, "high").Error(); got != "3 finding(s) at or above high" {
		t.Fatalf("gate message changed: %q", got)
	}
}

func TestSARIFToAFileCombinesWithOneStdoutMode(t *testing.T) {
	cases := []struct {
		name                    string
		jsonOut, sbomOut, sarif bool
		sarifPath               string
		owners                  int
	}{
		{name: "json alone", jsonOut: true, owners: 1},
		{name: "json with sarif-out", jsonOut: true, sarif: true, sarifPath: "out.sarif", owners: 1},
		{name: "sbom with sarif-out", sbomOut: true, sarif: true, sarifPath: "out.sarif", owners: 1},
		{name: "sarif-out alone", sarif: true, sarifPath: "out.sarif", owners: 0},
		{name: "json with sarif on stdout", jsonOut: true, sarif: true, owners: 2},
		{name: "json with sbom", jsonOut: true, sbomOut: true, owners: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := stdoutOwners(tc.jsonOut, tc.sbomOut, tc.sarif, tc.sarifPath); got != tc.owners {
				t.Fatalf("stdoutOwners = %d, want %d", got, tc.owners)
			}
		})
	}
}

// TestSubcommandGateAndUsagePathsCarryTheirCodes drives one subcommand through its real gate and option
// parsing, so a gate site that returns a plain error again, or an option error that reads as a runtime
// failure, turns this red.
func TestSubcommandGateAndUsagePathsCarryTheirCodes(t *testing.T) {
	dir := t.TempDir()
	body := ""
	for i := 0; i < 40; i++ {
		body += fmt.Sprintf("func f%d(a, b int) int {\n\tx := a*b + %d\n\tif x > 10 {\n\t\treturn x - a\n\t}\n\treturn x + b\n}\n", i, i)
	}
	for _, name := range []string{"a.go", "b.go"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("package p\n\n"+body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	quiet(t, func() {
		if got := exitCodeFor(runDuplication([]string{dir, "--fail-on-duplication", "1"})); got != exitGate {
			t.Errorf("duplication over threshold exits %d, want %d", got, exitGate)
		}
		if got := exitCodeFor(runDuplication([]string{dir, "--bogus"})); got != exitUsage {
			t.Errorf("an unknown duplication option exits %d, want %d", got, exitUsage)
		}
	})
}

// quiet runs fn with stdout discarded, so a subcommand's report does not flood the test log.
func quiet(t *testing.T, fn func()) {
	t.Helper()
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devnull.Close() }()
	saved := os.Stdout
	os.Stdout = devnull
	defer func() { os.Stdout = saved }()
	fn()
}
