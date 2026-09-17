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
		"GIT_CONFIG_NOSYSTEM: \"1\"",
		"GIT_CONFIG_COUNT: \"0\"",
		"GIT_CONFIG_PARAMETERS: \"\"",
		"GIT_TEMPLATE_DIR: \"\"",
		"git_config=\"$runner_temp/synapse-reachability-gitconfig\"",
		"printf 'GIT_CONFIG_GLOBAL=%s\\n' \"$git_config\" >> \"$GITHUB_ENV\"",
		"printf 'GIT_CONFIG_PARAMETERS=\\n' >> \"$GITHUB_ENV\"",
		"for name in \"${!GIT_@}\"; do",
		"GIT_CONFIG_NOSYSTEM|GIT_CONFIG_COUNT|GIT_CONFIG_PARAMETERS|GIT_TEMPLATE_DIR) ;;",
		"unexpected inherited Git environment variable: $name",
		"- name: Prepare fresh trusted checkout",
		"cd \"$RUNNER_TEMP\"",
		"realpath -m -- \"$workspace\"",
		"rm -f -- \"$git_config\"",
		"rm -rf -- \"$workspace\"",
		"install -d -m 0700 -- \"$workspace\"",
		"install -m 0600 /dev/null \"$git_config\"",
		"clean: true",
		"persist-credentials: false",
		"set-safe-directory: false",
		"fetch-depth: 0",
		"BASELINE_REVISION: \"50d205260be412dc2f57736f71d1448a8f58177a\"",
		"git reset --hard \"$SOURCE_SHA\"",
		"git clean -ffdx",
		"git rev-parse HEAD^{tree}",
		"objects/info/alternates",
		"refs/replace",
		"git config --local --get-regexp '^(include|includeif\\..*)\\.path$'",
		"git config --local --get core.hooksPath",
		"CONTROLLER_SOURCE_ROOT: ${{ vars.REACHABILITY_BENCHMARK_CONTROLLER_ROOT }}",
		"stage_root=\"$RUNNER_TEMP/synapse-reachability-controller\"",
		"controller staging root already exists",
		"export TMPDIR=\"$RUNNER_TEMP\"",
		"export SYNAPSE_REACHABILITY_CONTROLLER_ENVELOPE=\"$RUNNER_TEMP/synapse-reachability-controller/envelopes/$envelope_name\"",
		"find -P \"$controller_root\" -xdev -type l",
		"refs/heads/*) branch=",
		"git check-ref-format --branch \"$branch\"",
		"git rev-parse --is-shallow-repository",
		"git rev-parse --verify \"$BASELINE_REVISION^{commit}\"",
		"git merge-base --is-ancestor \"$BASELINE_REVISION\" \"$SOURCE_SHA\"",
		"git fetch --no-tags origin \"$TRUSTED_REF:refs/remotes/origin/$branch\"",
		"git rev-parse \"refs/remotes/origin/$branch\"",
		"assert_jdk_21 java",
		"assert_jdk_21 javac",
		"assert_jdk_21 jar",
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("workflow does not safely stage controller input: missing %q", required)
		}
	}
	if strings.Contains(workflow, "mv -- \"$workspace\"") || strings.Contains(workflow, "prior_checkout=") {
		t.Fatal("workflow must remove and recreate the validated checkout without quarantining or copying it")
	}
	if strings.Contains(workflow, "printf '%s=\\n' \"$name\" >> \"$GITHUB_ENV\"") {
		t.Fatal("workflow must reject unexpected inherited Git variables instead of persisting empty values")
	}
	if strings.Contains(workflow, "fetch-depth: 1") || strings.Contains(workflow, "git fetch --no-tags --depth=1") {
		t.Fatal("workflow must retain complete trusted ancestry for baseline identity checks")
	}
	teardown := strings.Index(workflow, "- name: Teardown trusted benchmark workspace")
	if teardown < 0 || !strings.Contains(workflow[teardown:], "if: ${{ always() }}") || !strings.Contains(workflow[teardown:], "\"$RUNNER_TEMP/synapse-reachability-gitconfig\"") || !strings.Contains(workflow[teardown:], "\"$RUNNER_TEMP/synapse-reachability-prior-checkout\"") {
		t.Fatal("workflow teardown must always remove isolated Git state")
	}
	const pristineStatus = "git status --porcelain=v1 --untracked-files=all --ignored=matching"
	if got := strings.Count(workflow, pristineStatus); got != 3 {
		t.Fatalf("workflow pristine checkout status checks = %d, want 3", got)
	}
	prepare := strings.Index(workflow, "- name: Prepare fresh trusted checkout")
	checkout := strings.Index(workflow, "- name: Check out exact source revision")
	assertion := strings.Index(workflow, "- name: Assert fresh checkout and protected reference head")
	setup := strings.Index(workflow, "- name: Set up Go")
	helperBuild := strings.Index(workflow, "go build -o \"$tools_root/synapse-callgraph\"")
	benchmark := strings.Index(workflow, "\n          make reachability-benchmark")
	if prepare < 0 || checkout < 0 || assertion < 0 || setup < 0 || helperBuild < 0 || benchmark < 0 || !(prepare < checkout && checkout < assertion && assertion < setup && setup < helperBuild && helperBuild < benchmark) {
		t.Fatal("workflow checkout preparation, assertion, setup, helper build, and benchmark are out of order")
	}
	if status := strings.LastIndex(workflow[:helperBuild], pristineStatus); status < strings.Index(workflow, "- name: Build trusted helpers") {
		t.Fatal("workflow does not recheck full clean status immediately before helper compilation")
	}
	if status := strings.LastIndex(workflow[:benchmark], pristineStatus); status < strings.Index(workflow, "- name: Run trusted benchmark") {
		t.Fatal("workflow does not recheck full clean status immediately before benchmark execution")
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
