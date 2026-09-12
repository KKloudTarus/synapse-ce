package main

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/enginecompare"
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

// TestRunCompareMode reduces two engines' finding sets into a differential (EPIC #860 D8.3): the candidate
// (owned) matches the baseline (grype) on the shared pair and adds one the baseline missed, so it matches
// baseline recall with one extra find.
func TestRunCompareMode(t *testing.T) {
	input := `{"baseline_name":"grype","candidate_name":"owned",` +
		`"baseline":[{"component":"curl","id":"CVE-1"}],` +
		`"candidate":[{"component":"curl","id":"CVE-1"},{"component":"curl","id":"CVE-2"}]}`
	var stdout bytes.Buffer
	if err := run("compare", "", "", strings.NewReader(input), &stdout); err != nil {
		t.Fatal(err)
	}
	var report enginecompare.Report
	if err := jsonUnmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.BaselineName != "grype" || report.CandidateName != "owned" {
		t.Fatalf("names = %q/%q", report.BaselineName, report.CandidateName)
	}
	if report.Both != 1 || len(report.CandidateOnly) != 1 || len(report.BaselineOnly) != 0 || !report.CandidateMatchesBaselineRecall {
		t.Fatalf("differential wrong: %+v", report)
	}
}

// An unknown mode is rejected (the message now lists compare).
func TestRunCompareUnknownMode(t *testing.T) {
	if err := run("bogus", "", "", strings.NewReader("{}"), &bytes.Buffer{}); err == nil {
		t.Fatal("unknown mode must error")
	}
}

// The compare input rejects an unknown/mistyped field rather than silently dropping it (which would
// understate a recall gap and overstate the owned engine).
func TestRunCompareRejectsUnknownField(t *testing.T) {
	input := `{"baseline_name":"grype","candidate_name":"owned","baseline":[{"component":"curl","advisory_id":"CVE-1"}],"candidate":[]}`
	if err := run("compare", "", "", strings.NewReader(input), &bytes.Buffer{}); err == nil {
		t.Fatal("a mistyped field (advisory_id) must be rejected, not silently dropped")
	}
}

// A case-variant duplicate key ("id" plus "ID") must be rejected, not silently accepted with the later
// value winning (which would drop a finding and overstate the owned engine). Go's default json matches
// field names case-insensitively, so this is validated case-sensitively.
func TestRunCompareRejectsCaseVariantKey(t *testing.T) {
	input := `{"baseline_name":"grype","candidate_name":"owned",` +
		`"baseline":[{"component":"curl","id":"CVE-2024-1","ID":"CVE-2024-2"}],"candidate":[]}`
	if err := run("compare", "", "", strings.NewReader(input), &bytes.Buffer{}); err == nil {
		t.Fatal("a case-variant duplicate key must be rejected")
	}
}

// An exact same-case duplicate key must be rejected (encoding/json would otherwise keep the last value and
// silently drop the first finding, overstating recall).
func TestRunCompareRejectsDuplicateKey(t *testing.T) {
	input := `{"baseline_name":"grype","candidate_name":"owned",` +
		`"baseline":[{"component":"curl","id":"CVE-2024-1","id":"CVE-2024-2"}],"candidate":[]}`
	if err := run("compare", "", "", strings.NewReader(input), &bytes.Buffer{}); err == nil {
		t.Fatal("a same-case duplicate key must be rejected")
	}
}

// rejectDuplicateJSONKeys errors on a repeat within one object, at any depth, but allows the same key name in
// DIFFERENT objects (and in array elements) so well-formed input is never falsely rejected.
func TestRejectDuplicateJSONKeys(t *testing.T) {
	bad := []string{
		`{"a":1,"a":2}`,
		`{"x":{"b":1,"b":2}}`,
		`{"arr":[{"c":1},{"c":2,"c":3}]}`,
	}
	for _, s := range bad {
		if err := rejectDuplicateJSONKeys([]byte(s)); err == nil {
			t.Errorf("expected duplicate-key error for %s", s)
		}
	}
	ok := []string{
		`{"a":1,"b":2}`,
		`{"arr":[{"c":1},{"c":2}]}`, // same key in different objects is fine
		`{"x":{"a":1},"y":{"a":2}}`, // same key in sibling objects is fine
		`{"component":"curl","id":"CVE-1","aliases":["CVE-2","CVE-3"]}`,
	}
	for _, s := range ok {
		if err := rejectDuplicateJSONKeys([]byte(s)); err != nil {
			t.Errorf("well-formed %s must not be rejected: %v", s, err)
		}
	}
}
