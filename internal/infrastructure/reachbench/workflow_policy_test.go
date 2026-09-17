package reachbench

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestReachabilityBenchmarkWorkflowPolicy(t *testing.T) {
	workflow := readReachabilityBenchmarkWorkflow(t)

	for _, action := range []string{
		"actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
		"actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
		"actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
	} {
		if !strings.Contains(workflow, action) {
			t.Fatalf("workflow does not pin %q", action)
		}
	}
	for _, match := range regexp.MustCompile(`(?m)^\s*uses:\s*[^@\s]+@([^\s#]+)`).FindAllStringSubmatch(workflow, -1) {
		if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(match[1]) {
			t.Fatalf("workflow action is not immutably pinned: %q", match[0])
		}
	}
	if !regexp.MustCompile(`(?m)^\s*make reachability-benchmark\s*$`).MatchString(workflow) {
		t.Fatal("workflow must invoke the exact no-argument reachability benchmark target")
	}
	if !strings.Contains(workflow, "workflow_dispatch:\n") || regexp.MustCompile(`(?m)^\s*workflow_dispatch:\s*\n\s+inputs:`).MatchString(workflow) {
		t.Fatal("workflow dispatch must not accept inputs")
	}
	for _, forbidden := range []string{
		"continue-on-error",
		"osv-scanner",
		"semgrep",
		"synapse-bench",
	} {
		if strings.Contains(strings.ToLower(workflow), forbidden) {
			t.Fatalf("workflow retains forbidden direct orchestration %q", forbidden)
		}
	}
	if strings.Count(workflow, "actions/upload-artifact@") != 1 || !strings.Contains(workflow, "path: ${{ runner.temp }}/synapse-reachability/published/github-${{ github.run_id }}/attempt-${{ github.run_attempt }}") {
		t.Fatal("workflow must upload only the known sanitized publication leaf")
	}
	for _, required := range []string{
		"CONTROLLER_SOURCE_ROOT: ${{ vars.REACHABILITY_BENCHMARK_CONTROLLER_ROOT }}",
		"stage_root=\"$RUNNER_TEMP/synapse-reachability-controller\"",
		"controller staging root already exists",
		"export TMPDIR=\"$RUNNER_TEMP\"",
		"export SYNAPSE_REACHABILITY_CONTROLLER_ENVELOPE=\"$RUNNER_TEMP/synapse-reachability-controller/envelopes/$envelope_name\"",
		"find -P \"$controller_root\" -xdev -type l",
		"refs/heads/*) branch=",
		"git check-ref-format --branch \"$branch\"",
		"git fetch --no-tags --depth=1 origin \"$TRUSTED_REF:refs/remotes/origin/$branch\"",
		"git rev-parse \"refs/remotes/origin/$branch\"",
		"assert_jdk_21 java",
		"assert_jdk_21 javac",
		"assert_jdk_21 jar",
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("workflow does not safely stage controller input: missing %q", required)
		}
	}
	for _, required := range []string{
		"aggregate:",
		"needs: [route, benchmark]",
		"test \"$ROUTE\" = success",
		"test \"$BENCHMARK\" = success",
		"test -n \"$ARTIFACT\"",
		"test \"$BENCHMARK\" = skipped",
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("workflow aggregate is incomplete: missing %q", required)
		}
	}
}

func readReachabilityBenchmarkWorkflow(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate workflow policy test source")
	}
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", ".github", "workflows", "reachability-benchmark.yml")
	workflow, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read reachability benchmark workflow: %v", err)
	}
	return strings.ReplaceAll(string(workflow), "\r\n", "\n")
}
