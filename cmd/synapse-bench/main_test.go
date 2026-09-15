package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/enginecompare"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/scabench"
)

func TestRunWritesDeterministicJSON(t *testing.T) {
	input := `{"schema_version":"synapse-benchmark-input-v1","metadata":{"environment":"fixture","environment_digest":"env","release":"release","release_digest":"rel","data_digest":"data"},"window":{"duration_milliseconds":1000},"requests":[{"duration_milliseconds":10,"succeeded":true}],"queue":{"delay_milliseconds":[2],"recovery_milliseconds":[3]},"pool":{"acquisition_milliseconds":[4],"saturation_events":0},"evidence":{"database_before_bytes":1,"database_after_bytes":2,"object_before_bytes":3,"object_after_bytes":5},"migration":{"duration_milliseconds":6},"api_failovers":[],"correctness":[]}`
	var stdout bytes.Buffer
	if err := run("throughput", "", "", "", strings.NewReader(input), &stdout); err != nil {
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
	err := run("throughput", "", "", "", strings.NewReader(`{"schema_version":"wrong"}`), &stdout)
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
	if err := run("accuracy", "", "", "", strings.NewReader(input), &stdout); err != nil {
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

// TestRunReachabilityMode gives owned-engine and OSS-adapter runners the same deterministic reduction
// contract: a scorecard is accepted only when every checked-in corpus case has an explicit label.
func TestRunReachabilityMode(t *testing.T) {
	input := `{"schema_version":"synapse-reachability-input-v1","corpus":{"schema_version":"synapse-reachability-corpus-v1","cases":[` +
		`{"name":"go-hit","language":"go","fixture":"fixture","symbol":"fixture.hit","expected":"reachable"},` +
		`{"name":"go-miss","language":"go","fixture":"fixture","symbol":"fixture.miss","expected":"present_unreached"}]},` +
		`"observations":[{"case":"go-hit","label":"reachable"},{"case":"go-miss","label":"present_unreached"}]}`
	var stdout bytes.Buffer
	if err := run("reachability", "", "", "", strings.NewReader(input), &stdout); err != nil {
		t.Fatal(err)
	}
	report, err := reachbench.LoadReport(&stdout)
	if err != nil {
		t.Fatalf("LoadReport: %v", err)
	}
	if report.SchemaVersion != reachbench.ReportSchemaVersion || report.Cases != 2 || report.Languages[0].PositiveRecall != 1 {
		t.Fatalf("report = %+v", report)
	}
}

func TestRunExternalReachabilityBaselineModes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  string
		input string
	}{
		{
			name:  "osv",
			mode:  "reachability-osv",
			input: `{"results":[{"source":{"path":"go_osv_jsonparser_called/go.mod"},"packages":[{"groups":[{"experimentalAnalysis":{"GO-2026-4514":{"called":true}}}]}]},{"source":{"path":"go_osv_jsonparser_uncalled/go.mod"},"packages":[{"groups":[{"experimentalAnalysis":{"GO-2026-4514":{"called":false}}}]}]}]}`,
		},
		{
			name:  "semgrep",
			mode:  "reachability-semgrep-ce",
			input: `{"results":[{"check_id":"reachbench.go.jsonparser-delete-called","path":"go_osv_jsonparser_called/main.go"}]}`,
		},
		{
			name:  "snyk sample",
			mode:  "reachability-snyk-sample",
			input: `{"observations":[{"evidence_id":"GO-2026-4514-called","label":"reachable"},{"evidence_id":"GO-2026-4514-uncalled","label":"present_unreached"}]}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout bytes.Buffer
			if err := run(tc.mode, "", "", "", strings.NewReader(tc.input), &stdout); err != nil {
				t.Fatal(err)
			}
			report, err := reachbench.LoadReport(&stdout)
			if err != nil {
				t.Fatal(err)
			}
			if report.Cases != len(reachbench.DefaultCorpus().Cases) || report.SchemaVersion != reachbench.ReportSchemaVersion {
				t.Fatalf("report = %+v", report)
			}
		})
	}
}

func TestRunRejectsUnknownMode(t *testing.T) {
	var stdout bytes.Buffer
	err := run("bogus", "", "", "", strings.NewReader(`{}`), &stdout)
	if err == nil || !strings.Contains(err.Error(), "unknown mode") {
		t.Fatalf("error = %v", err)
	}
}

func TestCLIExitsNonZeroForInvalidInput(t *testing.T) {
	var stderr bytes.Buffer
	if code := executeCLI(nil, strings.NewReader(`{"schema_version":"wrong"}`), &bytes.Buffer{}, &stderr); code != 1 {
		t.Fatalf("invalid legacy input exit code = %d", code)
	}
	if !strings.Contains(stderr.String(), "synapse-bench:") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestExecuteCLIPreservesHelpAndFlagParseExitCodes(t *testing.T) {
	if code := executeCLI([]string{"-h"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("help exit code = %d, want 0", code)
	}
	if code := executeCLI([]string{"-unknown"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); code != 2 {
		t.Fatalf("invalid flag exit code = %d, want 2", code)
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
	if err := run("compare", "", "", "", strings.NewReader(input), &stdout); err != nil {
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
	if err := run("bogus", "", "", "", strings.NewReader("{}"), &bytes.Buffer{}); err == nil {
		t.Fatal("unknown mode must error")
	}
}

// The compare input rejects an unknown/mistyped field rather than silently dropping it (which would
// understate a recall gap and overstate the owned engine).
func TestRunCompareRejectsUnknownField(t *testing.T) {
	input := `{"baseline_name":"grype","candidate_name":"owned","baseline":[{"component":"curl","advisory_id":"CVE-1"}],"candidate":[]}`
	if err := run("compare", "", "", "", strings.NewReader(input), &bytes.Buffer{}); err == nil {
		t.Fatal("a mistyped field (advisory_id) must be rejected, not silently dropped")
	}
}

// A case-variant duplicate key ("id" plus "ID") must be rejected, not silently accepted with the later
// value winning (which would drop a finding and overstate the owned engine). Go's default json matches
// field names case-insensitively, so this is validated case-sensitively.
func TestRunCompareRejectsCaseVariantKey(t *testing.T) {
	input := `{"baseline_name":"grype","candidate_name":"owned",` +
		`"baseline":[{"component":"curl","id":"CVE-2024-1","ID":"CVE-2024-2"}],"candidate":[]}`
	if err := run("compare", "", "", "", strings.NewReader(input), &bytes.Buffer{}); err == nil {
		t.Fatal("a case-variant duplicate key must be rejected")
	}
}

// An exact same-case duplicate key must be rejected (encoding/json would otherwise keep the last value and
// silently drop the first finding, overstating recall).
func TestRunCompareRejectsDuplicateKey(t *testing.T) {
	input := `{"baseline_name":"grype","candidate_name":"owned",` +
		`"baseline":[{"component":"curl","id":"CVE-2024-1","id":"CVE-2024-2"}],"candidate":[]}`
	if err := run("compare", "", "", "", strings.NewReader(input), &bytes.Buffer{}); err == nil {
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

// TestRunReachabilityBaselineLanguageFilter scopes a baseline report to one corpus language so its digest
// matches a language-scoped owned report (the parity gate rejects a full-corpus baseline against a
// language-scoped owned report). A python-scoped Semgrep baseline must contain only python cases.
func TestRunReachabilityBaselineLanguageFilter(t *testing.T) {
	base := "internal/infrastructure/tools/astwalk/testdata/reachbench"
	input := `{"results":[{"check_id":"reachbench.py.os-system-call","path":"` + base + `/py_reached/app.py"}]}`
	var stdout bytes.Buffer
	if err := run("reachability-semgrep-ce", "", "", "python", strings.NewReader(input), &stdout); err != nil {
		t.Fatal(err)
	}
	report, err := reachbench.LoadReport(&stdout)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Languages) != 1 || report.Languages[0].Language != "python" {
		t.Fatalf("language-scoped report must contain only python, got %+v", report.Languages)
	}
	pyCases := 0
	for _, c := range reachbench.DefaultCorpus().Cases {
		if c.Language == "python" {
			pyCases++
		}
	}
	if report.Cases != pyCases {
		t.Fatalf("python-scoped report has %d cases, want %d", report.Cases, pyCases)
	}
	// An unknown language fails closed rather than emitting an empty, vacuously-passing baseline.
	if err := run("reachability-semgrep-ce", "", "", "cobol", strings.NewReader(input), &bytes.Buffer{}); err == nil {
		t.Fatal("a language with no corpus cases must error")
	}
}

// TestRunRejectsLanguageForNonBaselineModes: -language only scopes an OSS-baseline report, so it is an error
// on modes that carry their own corpus (or none), never silently ignored.
func TestRunRejectsLanguageForNonBaselineModes(t *testing.T) {
	for _, mode := range []string{"reachability", "throughput", "accuracy", "compare"} {
		if err := run(mode, "", "", "python", strings.NewReader(`{}`), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "-language is only valid") {
			t.Fatalf("mode %q with -language must be rejected, got %v", mode, err)
		}
	}
}

func TestExecuteCLIRejectsInputForSCAAccuracy(t *testing.T) {
	var stderr bytes.Buffer
	if code := executeCLI([]string{"-mode", "sca-accuracy", "-input", "fixture.json"}, strings.NewReader(""), &bytes.Buffer{}, &stderr); code != 1 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "-input is not supported") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestSCAAccuracyGateFailureWritesValidatedResultBeforeExitTwo(t *testing.T) {
	fixture := writeSCAFixture(t, false)
	output := filepath.Join(t.TempDir(), "result.json")
	var stderr bytes.Buffer
	code := executeCLI([]string{
		"-mode", "sca-accuracy", "-catalog", fixture.catalogPath, "-oracle", fixture.oraclePath,
		"-ratchet", fixture.ratchetPath, "-observation", fixture.observationPaths[0], "-output", output,
	}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	file, err := os.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	result, err := scabench.DecodeResult(file)
	if err != nil {
		t.Fatalf("gate-failure output must be a valid result: %v", err)
	}
	if result.Gate == nil || result.Gate.Passed {
		t.Fatalf("gate evidence = %+v", result.Gate)
	}
}

func TestSCAAccuracyUnsupportedOnlyExitCodes(t *testing.T) {
	fixture := writeUnsupportedOnlySCAFixture(t)
	passingOutput := filepath.Join(t.TempDir(), "unsupported-pass.json")
	if code := executeCLI(scaAccuracyArgs(fixture, passingOutput), strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("unsupported-only passing exit code = %d", code)
	}
	passingFile, err := os.Open(passingOutput)
	if err != nil {
		t.Fatal(err)
	}
	passingResult, err := scabench.DecodeResult(passingFile)
	closeErr := passingFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if passingResult.Gate == nil || !passingResult.Gate.Passed {
		t.Fatalf("unsupported-only passing gate = %+v", passingResult.Gate)
	}
	for _, check := range passingResult.Gate.Checks {
		if check.Mode != scabench.FloorGateModeUnsupportedOnly {
			t.Fatalf("unsupported-only check mode = %+v", check)
		}
	}

	setSCAObservationState(t, fixture.observationPaths[0], scabench.ObservationIncomplete)
	failingOutput := filepath.Join(t.TempDir(), "unsupported-fail.json")
	if code := executeCLI(scaAccuracyArgs(fixture, failingOutput), strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); code != 2 {
		t.Fatalf("unsupported-only failing exit code = %d", code)
	}
	failingFile, err := os.Open(failingOutput)
	if err != nil {
		t.Fatal(err)
	}
	failingResult, err := scabench.DecodeResult(failingFile)
	closeErr = failingFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if failingResult.Gate == nil || failingResult.Gate.Passed {
		t.Fatalf("unsupported-only failing gate = %+v", failingResult.Gate)
	}
	foundPinMismatch := false
	for _, check := range failingResult.Gate.Checks {
		for _, reason := range check.ReasonCodes {
			if reason == scabench.GateReasonPinMismatch {
				foundPinMismatch = true
			}
		}
	}
	if !foundPinMismatch {
		t.Fatalf("unsupported-only failure did not retain capability pin evidence: %+v", failingResult.Gate)
	}
}

func TestSCAAccuracyRejectsUnsupportedObservationWithFindingsBeforeOutput(t *testing.T) {
	fixture := writeUnsupportedOnlySCAFixture(t)
	observationPath := fixture.observationPaths[0]
	body, err := os.ReadFile(observationPath)
	if err != nil {
		t.Fatal(err)
	}
	var set scabench.ObservationSet
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Observations) != 1 || set.Observations[0].State != scabench.ObservationUnsupported || set.Observations[0].CapabilityKind != scabench.CapabilityKindOSVScannerSUSERPM || set.Observations[0].CapabilityDigest == "" {
		t.Fatalf("fixture does not contain a pinned unsupported observation: %+v", set.Observations)
	}
	set.Observations[0].Findings = []scabench.Finding{{Component: scabench.Component{PURL: "pkg:npm/example@1.2.3"}, AdvisoryID: "CVE-2024-1111"}}
	body, err = json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(observationPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	output := filepath.Join(t.TempDir(), "result.json")
	if err := os.WriteFile(output, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	code := executeCLI(scaAccuracyArgs(fixture, output), strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if code != 1 {
		t.Fatalf("unsupported observation with findings exit code = %d", code)
	}
	published, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(published) != "sentinel" {
		t.Fatalf("invalid unsupported observation changed output: %q", published)
	}
}

func TestSCAAccuracyMalformedInputLeavesExistingOutputUntouched(t *testing.T) {
	directory := t.TempDir()
	catalog := filepath.Join(directory, "bad-catalog.json")
	output := filepath.Join(directory, "result.json")
	if err := os.WriteFile(catalog, []byte(`{"schema_version":"bad"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	code := executeCLI([]string{
		"-mode", "sca-accuracy", "-catalog", catalog, "-oracle", catalog, "-ratchet", catalog,
		"-observation", catalog, "-output", output,
	}, strings.NewReader(""), &bytes.Buffer{}, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "sentinel" {
		t.Fatalf("malformed input changed output: %q", body)
	}
}

func TestSCAAccuracyRejectsOversizedResultWithoutPublishing(t *testing.T) {
	fixture := writeSCAFixture(t, true)
	extendSCAFixtureEngineVersions(t, fixture, strings.Repeat("x", 500_000))
	output := filepath.Join(t.TempDir(), "result.json")
	if err := os.WriteFile(output, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	if code := executeCLI(scaAccuracyArgs(fixture, output), strings.NewReader(""), &bytes.Buffer{}, &stderr); code != 1 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "8388608") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "sentinel" {
		t.Fatalf("oversized result changed output: %q", body)
	}
}

func TestWriteOutputPreservesExistingFileWhenEncodingFails(t *testing.T) {
	output := filepath.Join(t.TempDir(), "result.json")
	if err := os.WriteFile(output, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := writeOutput(output, &bytes.Buffer{}, func(writer io.Writer) error {
		if _, err := writer.Write([]byte("partial")); err != nil {
			return err
		}
		return os.ErrInvalid
	})
	if err == nil {
		t.Fatal("writeOutput accepted failed encoding")
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "sentinel" {
		t.Fatalf("failed output publication changed existing file: %q", body)
	}
}

func TestWriteOutputAtomicallyReplacesExistingFileAfterSuccessfulEncoding(t *testing.T) {
	output := filepath.Join(t.TempDir(), "result.json")
	if err := os.WriteFile(output, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeOutput(output, &bytes.Buffer{}, func(writer io.Writer) error {
		_, err := writer.Write([]byte("new"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "new" {
		t.Fatalf("published output = %q, want new", body)
	}
}

func TestSCAAccuracyObservationOrderingDoesNotChangeResult(t *testing.T) {
	fixture := writeSCAFixture(t, true)
	first := filepath.Join(t.TempDir(), "first.json")
	second := filepath.Join(t.TempDir(), "second.json")
	arguments := func(output string, observations []string) []string {
		args := []string{"-mode", "sca-accuracy", "-catalog", fixture.catalogPath, "-oracle", fixture.oraclePath, "-ratchet", fixture.ratchetPath, "-output", output}
		for _, observation := range observations {
			args = append(args, "-observation", observation)
		}
		return args
	}
	if code := executeCLI(arguments(first, fixture.observationPaths), strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("first exit code = %d", code)
	}
	reversed := append([]string(nil), fixture.observationPaths...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	if code := executeCLI(arguments(second, reversed), strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("second exit code = %d", code)
	}
	firstBody, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondBody, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBody, secondBody) {
		t.Fatalf("observation order changed result:\n%s\n---\n%s", firstBody, secondBody)
	}
}

func TestSCAAccuracyRejectsCrossFileDuplicateBeforeOutput(t *testing.T) {
	fixture := writeSCAFixture(t, true)
	output := filepath.Join(t.TempDir(), "result.json")
	if err := os.WriteFile(output, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	code := executeCLI([]string{
		"-mode", "sca-accuracy", "-catalog", fixture.catalogPath, "-oracle", fixture.oraclePath, "-ratchet", fixture.ratchetPath,
		"-observation", fixture.observationPaths[0], "-observation", fixture.observationPaths[0], "-output", output,
	}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if code != 1 {
		t.Fatalf("duplicate observation exit code = %d", code)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "sentinel" {
		t.Fatalf("duplicate input changed output: %q", body)
	}
}

func TestSCARenderAndCompareManyModes(t *testing.T) {
	fixture := writeSCAFixture(t, true)
	resultPath := filepath.Join(t.TempDir(), "result.json")
	args := scaAccuracyArgs(fixture, resultPath)
	if code := executeCLI(args, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("sca accuracy exit code = %d", code)
	}
	var rendered bytes.Buffer
	if code := executeCLI([]string{"-mode", "sca-render", "-input", resultPath}, strings.NewReader(""), &rendered, &bytes.Buffer{}); code != 0 || !strings.Contains(rendered.String(), "SCA Benchmark Result") {
		t.Fatalf("render exit/output = %d / %q", code, rendered.String())
	}
	inputIdentity := `{"catalog_revision":"r1","catalog_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","target_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","sbom_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`
	many := `{"candidate":{"name":"owned","input_identity":` + inputIdentity + `,"findings":[{"component":"curl","id":"CVE-1"}]},"baselines":[{"name":"trivy","input_identity":` + inputIdentity + `,"findings":[{"component":"curl","id":"CVE-2"}]},{"name":"grype","input_identity":` + inputIdentity + `,"findings":[{"component":"curl","id":"CVE-1"}]}]}`
	var differential bytes.Buffer
	if code := executeCLI([]string{"-mode", "compare-many"}, strings.NewReader(many), &differential, &bytes.Buffer{}); code != 0 {
		t.Fatalf("compare-many exit code = %d", code)
	}
	var report enginecompare.MultiReport
	if err := json.Unmarshal(differential.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.DiagnosticOnly || len(report.Comparisons) != 2 || report.Comparisons[0].BaselineName != "grype" {
		t.Fatalf("compare-many report = %+v", report)
	}
}

func TestCompareDecodersEnforceBoundedStrictJSON(t *testing.T) {
	for _, test := range []struct {
		name  string
		input []byte
	}{
		{name: "oversized", input: []byte(strings.Repeat(" ", int(scabench.MaxJSONBytes)+1))},
		{name: "invalid UTF-8", input: []byte{'{', 0xff, '}'}},
		{name: "multiple values", input: []byte(`{} {}`)},
		{name: "nested beyond limit", input: []byte(strings.Repeat("[", maxCompareJSONDepth+1) + "0" + strings.Repeat("]", maxCompareJSONDepth+1))},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeCompare(bytes.NewReader(test.input)); err == nil {
				t.Fatal("compare decoder accepted invalid bounded JSON input")
			}
			if _, err := decodeManyCompare(bytes.NewReader(test.input)); err == nil {
				t.Fatal("compare-many decoder accepted invalid bounded JSON input")
			}
		})
	}
}

func TestCompareDecodersRejectUnicodeCaseFoldCollisions(t *testing.T) {
	compareInput := `{"baseline_name":"baseline","candidate_name":"candidate","baseline":[],"candidate":[],"S":[],"ſ":[]}`
	if _, err := decodeCompare(strings.NewReader(compareInput)); err == nil || !strings.Contains(err.Error(), "case-fold duplicate") {
		t.Fatalf("compare decoder error = %v, want Unicode case-fold collision", err)
	}

	manyInput := `{"candidate":{"name":"candidate","findings":[],"S":[],"ſ":[]},"baselines":[{"name":"baseline","findings":[]}]}`
	if _, err := decodeManyCompare(strings.NewReader(manyInput)); err == nil || !strings.Contains(err.Error(), "case-fold duplicate") {
		t.Fatalf("compare-many decoder error = %v, want Unicode case-fold collision", err)
	}
}

func TestCompareManyStrictlyDecodesInputIdentity(t *testing.T) {
	identity := `{"catalog_revision":"r1","catalog_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","target_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","sbom_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`
	for _, test := range []struct {
		name     string
		identity string
	}{
		{name: "unknown field", identity: strings.TrimSuffix(identity, "}") + `,"extra":"x"}`},
		{name: "case variant", identity: strings.Replace(identity, `"catalog_revision"`, `"Catalog_Revision"`, 1)},
		{name: "case-fold duplicate", identity: strings.TrimSuffix(identity, "}") + `,"Catalog_Revision":"r2"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := `{"candidate":{"name":"owned","input_identity":` + test.identity + `,"findings":[]},"baselines":[{"name":"grype","input_identity":` + identity + `,"findings":[]}]}`
			if _, err := decodeManyCompare(strings.NewReader(input)); err == nil {
				t.Fatal("compare-many accepted a non-strict input_identity")
			}
		})
	}
}

func TestNamedInputsCannotBeOutputPaths(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "input.json")
	if err := os.WriteFile(input, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run("throughput", input, input, "", strings.NewReader(""), &bytes.Buffer{}); err == nil {
		t.Fatal("run allowed output to overwrite its named input")
	}
	if err := runCompareMany(input, input, strings.NewReader(""), &bytes.Buffer{}); err == nil {
		t.Fatal("compare-many allowed output to overwrite its named input")
	}
	if err := runSCARender(input, input, &bytes.Buffer{}); err == nil {
		t.Fatal("sca-render allowed output to overwrite its named input")
	}
	fixture := writeSCAFixture(t, true)
	if err := runSCAAccuracy(fixture.catalogPath, fixture.oraclePath, fixture.ratchetPath, fixture.observationPaths, fixture.catalogPath, &bytes.Buffer{}); err == nil {
		t.Fatal("sca-accuracy allowed output to overwrite a named input")
	}
}

func TestNamedInputOutputAliasIsRejected(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "input.json")
	alias := filepath.Join(directory, "output-alias.json")
	if err := os.WriteFile(input, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(input, alias); err != nil {
		if os.IsPermission(err) || errors.Is(err, syscall.Errno(1314)) {
			t.Skipf("symlink setup unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if err := run("throughput", input, alias, "", strings.NewReader(""), &bytes.Buffer{}); err == nil {
		t.Fatal("run allowed an output symlink to overwrite its named input")
	}
	if runtime.GOOS == "windows" {
		caseAlias := strings.ToUpper(input)
		if err := run("throughput", input, caseAlias, "", strings.NewReader(""), &bytes.Buffer{}); err == nil {
			t.Fatal("run allowed a case-alias output to overwrite its named input")
		}
	}
}

func TestCompareOutputLimitsLeaveDestinationsUntouched(t *testing.T) {
	component := strings.Repeat("component-", 128)
	aliases := make([]string, 0, 9000)
	for i := 0; i < cap(aliases); i++ {
		aliases = append(aliases, `"CVE-2024-`+strconv.Itoa(i)+`"`)
	}
	finding := `{"component":"` + component + `","id":"vendor-id","aliases":[` + strings.Join(aliases, ",") + `]}`
	identity := `{"catalog_revision":"r1","catalog_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","target_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","sbom_digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`
	for _, test := range []struct {
		name  string
		input string
		run   func(string, string, io.Reader, io.Writer) error
	}{
		{name: "compare", input: `{"baseline_name":"grype","candidate_name":"owned","baseline":[],"candidate":[` + finding + `]}`, run: func(inputPath, outputPath string, input io.Reader, output io.Writer) error {
			return run("compare", inputPath, outputPath, "", input, output)
		}},
		{name: "compare-many", input: `{"candidate":{"name":"owned","input_identity":` + identity + `,"findings":[` + finding + `]},"baselines":[{"name":"grype","input_identity":` + identity + `,"findings":[]}]}`, run: runCompareMany},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "result.json")
			if err := os.WriteFile(output, []byte("sentinel"), 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout bytes.Buffer
			if err := test.run("", output, strings.NewReader(test.input), &stdout); err == nil {
				t.Fatal("oversized compare output was published")
			}
			if stdout.Len() != 0 {
				t.Fatal("oversized compare output wrote partial stdout")
			}
			body, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != "sentinel" {
				t.Fatalf("oversized compare output replaced destination: %q", body)
			}
		})
	}
}

func TestCLIChildExitCodesWithoutGoRun(t *testing.T) {
	if encoded := os.Getenv("SYNAPSE_BENCH_CHILD_ARGS"); encoded != "" {
		var args []string
		if err := json.Unmarshal([]byte(encoded), &args); err != nil {
			os.Exit(99)
		}
		os.Exit(executeCLI(args, os.Stdin, os.Stdout, os.Stderr))
	}
	fixture := writeSCAFixture(t, false)
	runChild := func(args []string) int {
		encoded, err := json.Marshal(args)
		if err != nil {
			t.Fatal(err)
		}
		command := exec.Command(os.Args[0], "-test.run=^TestCLIChildExitCodesWithoutGoRun$")
		command.Env = append(os.Environ(), "SYNAPSE_BENCH_CHILD_ARGS="+string(encoded))
		if err := command.Run(); err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				return exit.ExitCode()
			}
			t.Fatal(err)
		}
		return 0
	}
	if code := runChild([]string{"-mode", "sca-accuracy", "-input", "forbidden"}); code != 1 {
		t.Fatalf("malformed child exit = %d", code)
	}
	passing := writeSCAFixture(t, true)
	passOutput := filepath.Join(t.TempDir(), "pass-result.json")
	if code := runChild(scaAccuracyArgs(passing, passOutput)); code != 0 {
		t.Fatalf("passing child exit = %d", code)
	}
	output := filepath.Join(t.TempDir(), "child-result.json")
	if code := runChild([]string{"-mode", "sca-accuracy", "-catalog", fixture.catalogPath, "-oracle", fixture.oraclePath, "-ratchet", fixture.ratchetPath, "-observation", fixture.observationPaths[0], "-output", output}); code != 2 {
		t.Fatalf("gate-failed child exit = %d", code)
	}
}

func intPointer(value int) *int { return &value }

func floatPointer(value float64) *float64 { return &value }

func expectedRunIdentity(run scabench.RunIdentity) scabench.ExpectedRunIdentity {
	return scabench.ExpectedRunIdentity{
		TargetID:           run.TargetID,
		TargetDigest:       run.TargetDigest,
		SBOMDigest:         run.SBOMDigest,
		Engine:             run.Engine,
		EngineVersion:      run.EngineVersion,
		EngineBinaryDigest: run.EngineBinaryDigest,
		DatabaseBuild:      run.DatabaseBuild,
		DatabaseDigest:     run.DatabaseDigest,
		EnvironmentID:      run.EnvironmentID,
		EnvironmentDigest:  run.EnvironmentDigest,
		ConfigDigest:       run.ConfigDigest,
		CapabilityKind:     run.CapabilityKind,
		CapabilityDigest:   run.CapabilityDigest,
	}
}

type scaFixture struct {
	catalogPath      string
	oraclePath       string
	ratchetPath      string
	observationPaths []string
}

func scaAccuracyArgs(fixture scaFixture, output string) []string {
	args := []string{"-mode", "sca-accuracy", "-catalog", fixture.catalogPath, "-oracle", fixture.oraclePath, "-ratchet", fixture.ratchetPath}
	for _, observation := range fixture.observationPaths {
		args = append(args, "-observation", observation)
	}
	return append(args, "-output", output)
}

func writeSCAFixture(t *testing.T, pass bool) scaFixture {
	t.Helper()
	directory := t.TempDir()
	digest := func(character string) string { return "sha256:" + strings.Repeat(character, 64) }
	catalog := scabench.Catalog{
		SchemaVersion: scabench.CatalogSchemaVersion,
		Revision:      "r1",
		Targets: []scabench.Target{{
			ID: "image", OCIRef: "registry.example/test@" + digest("a"), Digest: digest("a"), SBOMDigest: digest("b"),
			Components: []scabench.Component{{PURL: "pkg:npm/example@1.2.3"}},
		}},
	}
	catalogDigest, err := scabench.DigestCatalog(catalog)
	if err != nil {
		t.Fatal(err)
	}
	oracle := scabench.Oracle{
		SchemaVersion: scabench.OracleSchemaVersion, CatalogRevision: catalog.Revision,
		Cases: []scabench.OracleCase{
			{
				ID: "affected", Classification: scabench.CaseReal, TargetID: "image", Component: catalog.Targets[0].Components[0], AdvisoryID: "CVE-2024-1111", Truth: scabench.TruthAffected,
				ExpectedCoverage: map[scabench.Engine]scabench.Coverage{scabench.EngineOwned: scabench.CoverageCovered, scabench.EngineGrype: scabench.CoverageCovered, scabench.EngineTrivy: scabench.CoverageCovered, scabench.EngineOSVScanner: scabench.CoverageCovered},
				Provenance:       scabench.ProvenanceIndependent, ReviewStatus: scabench.ReviewApproved, LabelerIDs: []string{"labeler"}, ReviewerIDs: []string{"reviewer"}, Rationale: "reviewed", Citations: []scabench.Citation{{Reference: "https://evidence.example/cve-affected", Digest: digest("c")}},
			},
			{
				ID: "fixed", Classification: scabench.CaseReal, TargetID: "image", Component: catalog.Targets[0].Components[0], AdvisoryID: "CVE-2024-2222", Truth: scabench.TruthFixed,
				ExpectedCoverage: map[scabench.Engine]scabench.Coverage{scabench.EngineOwned: scabench.CoverageCovered, scabench.EngineGrype: scabench.CoverageCovered, scabench.EngineTrivy: scabench.CoverageCovered, scabench.EngineOSVScanner: scabench.CoverageCovered},
				Provenance:       scabench.ProvenanceIndependent, ReviewStatus: scabench.ReviewApproved, LabelerIDs: []string{"labeler"}, ReviewerIDs: []string{"reviewer"}, Rationale: "reviewed", Citations: []scabench.Citation{{Reference: "https://evidence.example/cve-fixed", Digest: digest("c")}},
			},
		},
	}
	observation := func(engine scabench.Engine) scabench.Observation {
		findings := []scabench.Finding(nil)
		if pass {
			findings = []scabench.Finding{{Component: catalog.Targets[0].Components[0], AdvisoryID: "CVE-2024-1111"}}
		}
		return scabench.Observation{
			SchemaVersion: scabench.ObservationSchemaVersion, CatalogRevision: catalog.Revision, CatalogDigest: catalogDigest,
			Engine: engine, EngineVersion: string(engine) + "-v1", EngineBinaryDigest: digest("d"), DatabaseBuild: "database-r1", DatabaseDigest: digest("e"),
			EnvironmentID: "test-linux", EnvironmentDigest: digest("f"), TargetID: "image", TargetDigest: catalog.Targets[0].Digest, SBOMDigest: catalog.Targets[0].SBOMDigest,
			State: scabench.ObservationComplete, RawOutputDigest: digest("1"), ConfigDigest: digest("2"), Findings: findings,
		}
	}
	observations := make([]scabench.Observation, 0, 4)
	for _, engine := range []scabench.Engine{scabench.EngineOwned, scabench.EngineGrype, scabench.EngineTrivy, scabench.EngineOSVScanner} {
		observations = append(observations, observation(engine))
	}
	base, err := scabench.Reduce(catalog, oracle, observations)
	if err != nil {
		t.Fatal(err)
	}
	floors := make([]scabench.RatchetFloor, 0, len(base.Runs))
	for _, run := range base.Runs {
		floors = append(floors, scabench.RatchetFloor{
			Expected: expectedRunIdentity(run), MinimumCovered: intPointer(2), MinimumAffectedRelations: intPointer(1), MinimumNegativeRelations: intPointer(1), MinimumPrecision: floatPointer(0), MinimumRecall: floatPointer(0), MaximumFalsePositives: intPointer(0), MaximumFalseNegatives: intPointer(0), MaximumUnknown: intPointer(0), MaximumIncomplete: intPointer(0), MaximumUnsupported: intPointer(0),
		})
	}
	oracleDigest, err := scabench.DigestOracle(oracle)
	if err != nil {
		t.Fatal(err)
	}
	ratchet := scabench.Ratchet{SchemaVersion: scabench.RatchetSchemaVersion, CatalogRevision: catalog.Revision, CatalogDigest: catalogDigest, OracleDigest: oracleDigest, Floors: floors}
	write := func(name string, value any) string {
		path := filepath.Join(directory, name)
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	observationPaths := make([]string, 0, len(observations))
	for _, captured := range observations {
		observationPaths = append(observationPaths, write(string(captured.Engine)+".json", scabench.ObservationSet{SchemaVersion: scabench.ObservationSchemaVersion, CatalogRevision: catalog.Revision, CatalogDigest: catalogDigest, Observations: []scabench.Observation{captured}}))
	}
	return scaFixture{catalogPath: write("catalog.json", catalog), oraclePath: write("oracle.json", oracle), ratchetPath: write("ratchet.json", ratchet), observationPaths: observationPaths}
}

func writeUnsupportedOnlySCAFixture(t *testing.T) scaFixture {
	t.Helper()
	fixture := writeSCAFixture(t, false)
	for _, observationPath := range fixture.observationPaths {
		setSCAObservationState(t, observationPath, scabench.ObservationUnsupported)
	}
	oracleBody, err := os.ReadFile(fixture.oraclePath)
	if err != nil {
		t.Fatal(err)
	}
	var oracle scabench.Oracle
	if err := json.Unmarshal(oracleBody, &oracle); err != nil {
		t.Fatal(err)
	}
	for i := range oracle.Cases {
		oracle.Cases[i].ExpectedCoverage = make(map[scabench.Engine]scabench.Coverage, len(scabench.Engines()))
		for _, engine := range scabench.Engines() {
			oracle.Cases[i].ExpectedCoverage[engine] = scabench.CoverageUnsupported
		}
	}
	oracleDigest, err := scabench.DigestOracle(oracle)
	if err != nil {
		t.Fatal(err)
	}
	oracleBody, err = json.Marshal(oracle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.oraclePath, oracleBody, 0o600); err != nil {
		t.Fatal(err)
	}

	ratchetBody, err := os.ReadFile(fixture.ratchetPath)
	if err != nil {
		t.Fatal(err)
	}
	var ratchet scabench.Ratchet
	if err := json.Unmarshal(ratchetBody, &ratchet); err != nil {
		t.Fatal(err)
	}
	ratchet.OracleDigest = oracleDigest
	for i := range ratchet.Floors {
		floor := &ratchet.Floors[i]
		floor.Expected.CapabilityKind = scabench.CapabilityKindOSVScannerSUSERPM
		floor.Expected.CapabilityDigest = "sha256:" + strings.Repeat("8", 64)
		floor.Mode = scabench.FloorGateModeUnsupportedOnly
		floor.MinimumCovered = intPointer(0)
		floor.MinimumAffectedRelations = intPointer(0)
		floor.MinimumNegativeRelations = intPointer(0)
		floor.MinimumPrecision = floatPointer(0)
		floor.MinimumRecall = floatPointer(0)
		floor.MaximumFalsePositives = intPointer(0)
		floor.MaximumFalseNegatives = intPointer(0)
		floor.MaximumUnknown = intPointer(0)
		floor.MaximumIncomplete = intPointer(0)
		floor.MaximumUnsupported = intPointer(2)
	}
	ratchetBody, err = json.Marshal(ratchet)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.ratchetPath, ratchetBody, 0o600); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func setSCAObservationState(t *testing.T, path string, state scabench.ObservationState) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var set scabench.ObservationSet
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Observations) != 1 {
		t.Fatalf("fixture observation set has %d observations", len(set.Observations))
	}
	set.Observations[0].State = state
	if state == scabench.ObservationUnsupported {
		set.Observations[0].CapabilityKind = scabench.CapabilityKindOSVScannerSUSERPM
		set.Observations[0].CapabilityDigest = "sha256:" + strings.Repeat("8", 64)
	} else {
		set.Observations[0].CapabilityKind = ""
		set.Observations[0].CapabilityDigest = ""
	}
	body, err = json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func extendSCAFixtureEngineVersions(t *testing.T, fixture scaFixture, suffix string) {
	t.Helper()
	for _, path := range fixture.observationPaths {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var set scabench.ObservationSet
		if err := json.Unmarshal(body, &set); err != nil {
			t.Fatal(err)
		}
		if len(set.Observations) != 1 {
			t.Fatalf("fixture observation set has %d observations", len(set.Observations))
		}
		set.Observations[0].EngineVersion += suffix
		body, err = json.Marshal(set)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	body, err := os.ReadFile(fixture.ratchetPath)
	if err != nil {
		t.Fatal(err)
	}
	var ratchet scabench.Ratchet
	if err := json.Unmarshal(body, &ratchet); err != nil {
		t.Fatal(err)
	}
	for i := range ratchet.Floors {
		ratchet.Floors[i].Expected.EngineVersion += suffix
	}
	body, err = json.Marshal(ratchet)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.ratchetPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
