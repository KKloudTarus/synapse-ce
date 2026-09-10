package main

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

func TestRunWritesDeterministicJSON(t *testing.T) {
	input := `{"schema_version":"synapse-benchmark-input-v1","metadata":{"environment":"fixture","environment_digest":"env","release":"release","release_digest":"rel","data_digest":"data"},"window":{"duration_milliseconds":1000},"requests":[{"duration_milliseconds":10,"succeeded":true}],"queue":{"delay_milliseconds":[2],"recovery_milliseconds":[3]},"pool":{"acquisition_milliseconds":[4],"saturation_events":0},"evidence":{"database_before_bytes":1,"database_after_bytes":2,"object_before_bytes":3,"object_after_bytes":5},"migration":{"duration_milliseconds":6},"api_failovers":[],"correctness":[]}`
	var stdout bytes.Buffer
	if err := run("throughput", "", "", strings.NewReader(input), &stdout); err != nil {
		t.Fatal(err)
	}
	var report benchmark.Report
	if err := jsonUnmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != benchmark.OutputSchemaVersion || report.Throughput.RequestsPerSecond != 1 || report.Requests.Failures != 0 {
		t.Fatalf("report = %+v", report)
	}
}

func TestRunReturnsErrorForInvalidInput(t *testing.T) {
	var stdout bytes.Buffer
	err := run("throughput", "", "", strings.NewReader(`{"schema_version":"wrong"}`), &stdout)
	if err == nil || !strings.Contains(err.Error(), "evaluate benchmark input") {
		t.Fatalf("error = %v", err)
	}
}

// TestRunAccuracyMode reduces a detection-accuracy input into a precision/recall report (D8.2 exposure via
// synapse-bench).
func TestRunAccuracyMode(t *testing.T) {
	input := `{"schema_version":"synapse-accuracy-input-v1","observations":[` +
		`{"case":"c1","group":"npm","expected":["pkg|CVE-1"],"produced":["pkg|CVE-1"]},` +
		`{"case":"c2","group":"npm","expected":["pkg|CVE-2"],"produced":["pkg|CVE-2","pkg|CVE-9"]}]}`
	var stdout bytes.Buffer
	if err := run("accuracy", "", "", strings.NewReader(input), &stdout); err != nil {
		t.Fatal(err)
	}
	var report benchmark.AccuracyReport
	if err := jsonUnmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != benchmark.AccuracyReportSchemaVersion {
		t.Fatalf("schema = %q", report.SchemaVersion)
	}
	// TP=2 (both CVE-1, CVE-2), FP=1 (CVE-9), FN=0: recall 1.0, precision 2/3.
	if report.Overall.TruePositives != 2 || report.Overall.FalsePositives != 1 || report.Overall.Recall != 1 {
		t.Fatalf("overall = %+v", report.Overall)
	}
}

func TestRunRejectsUnknownMode(t *testing.T) {
	var stdout bytes.Buffer
	err := run("bogus", "", "", strings.NewReader(`{}`), &stdout)
	if err == nil || !strings.Contains(err.Error(), "unknown mode") {
		t.Fatalf("error = %v", err)
	}
}

func TestCLIExitsNonZeroForInvalidInput(t *testing.T) {
	command := exec.Command("go", "run", ".")
	command.Stdin = strings.NewReader(`{"schema_version":"wrong"}`)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err == nil {
		t.Fatal("CLI succeeded with invalid input")
	}
	if !strings.Contains(stderr.String(), "synapse-bench:") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func jsonUnmarshal(data []byte, value any) error {
	return json.Unmarshal(data, value)
}
