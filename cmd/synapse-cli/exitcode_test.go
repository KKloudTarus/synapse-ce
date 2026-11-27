package main

import (
	"errors"
	"fmt"
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
