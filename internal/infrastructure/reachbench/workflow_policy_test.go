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
	if strings.Count(workflow, "make reachability-benchmark") < 2 {
		t.Fatal("workflow must run both the PR-safe and trusted no-argument lifecycles")
	}
	if !strings.Contains(workflow, "workflow_dispatch:\n") || regexp.MustCompile(`(?m)^\s*workflow_dispatch:\s*\n\s+inputs:`).MatchString(workflow) {
		t.Fatal("workflow dispatch must not accept inputs")
	}
	for _, forbidden := range []string{
		"continue-on-error",
		"REACHABILITY_BENCHMARK_TRUSTED_SHA",
	} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("workflow retains forbidden policy surface %q", forbidden)
		}
	}

	for _, required := range []string{
		"pull_request:\n    branches: [main]",
		"schedule:",
		"workflow_dispatch:",
		`if [ "$EVENT_NAME" != pull_request ] && [ "$ENABLED" = true ] && [ -n "$TRUSTED_REF" ] && [ "$REF" = "$TRUSTED_REF" ]; then`,
		"pr-lifecycle:",
		"name: PR-safe reachability lifecycle",
		"if: ${{ github.event_name == 'pull_request' }}",
		"name: Upload SHA-bound lifecycle evidence",
		"go-oss-baselines:",
		"name: Go corpus vs OSV-Scanner and Semgrep CE",
		"python-oss-baselines:",
		"name: Python corpus vs Semgrep CE",
		"github.com/google/osv-scanner/v2/cmd/osv-scanner@${OSV_SCANNER_VERSION}",
		"semgrep/semgrep@sha256:d39aa8d8cdb7fd9e5ec14f0825e2356f902129778c9617217856295e553254d5",
		"docker run --rm --network none --user",
		"-e SEMGREP_ENABLE_VERSION_CHECK=0 -e EIO_BACKEND=posix",
		"scan --oss-only --metrics off --jobs 1 --config",
		"go run ./cmd/synapse-bench -mode reachability-osv",
		"go run ./cmd/synapse-bench -mode reachability-semgrep-ce -language go",
		"go run ./cmd/synapse-bench -mode reachability-semgrep-ce -language python",
		"TestGoReachabilityCorpus",
		"TestPythonReachabilityCorpus",
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("workflow does not provide the required benchmark path: missing %q", required)
		}
	}

	for _, required := range []string{
		"GIT_CONFIG_NOSYSTEM: \"1\"",
		"GIT_CONFIG_COUNT: \"0\"",
		"GIT_CONFIG_PARAMETERS: \"\"",
		"GIT_TEMPLATE_DIR: \"\"",
		"git_config=\"$runner_temp/synapse-reachability-gitconfig\"",
		"printf 'GIT_CONFIG_GLOBAL=%s\\n' \"$git_config\" >> \"$GITHUB_ENV\"",
		"for name in \"${!GIT_@}\"; do",
		"unexpected inherited Git environment variable: $name",
		"- name: Prepare fresh trusted checkout",
		"clean: true",
		"persist-credentials: false",
		"set-safe-directory: false",
		"fetch-depth: 0",
		"BASELINE_REVISION: \"50d205260be412dc2f57736f71d1448a8f58177a\"",
		"git reset --hard \"$SOURCE_SHA\"",
		"git clean -ffdx",
		"objects/info/alternates",
		"refs/replace",
		"git config --local --get-regexp '^(include|includeif\\..*)\\.path$'",
		"CONTROLLER_SOURCE_ROOT: ${{ vars.REACHABILITY_BENCHMARK_CONTROLLER_ROOT }}",
		"stage_root=\"$RUNNER_TEMP/synapse-reachability-controller\"",
		"controller authority inventory is not exact",
		"controller authority entry exceeds the JSON size bound",
		"git fetch --no-tags origin \"$TRUSTED_REF:refs/remotes/origin/$branch\"",
		"assert_jdk_21 java",
		"assert_jdk_21 javac",
		"assert_jdk_21 jar",
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("workflow does not safely stage trusted input: missing %q", required)
		}
	}

	for _, required := range []string{
		"- name: Run trusted benchmark from private immutable source",
		"unshare --user --map-root-user --mount --fork --pid --mount-proc",
		"mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs \"$PRIVATE_MOUNT\"",
		"git clone --no-local --no-hardlinks --no-checkout -- \"$HOST_CHECKOUT\" \"$source_root\"",
		"git checkout --detach \"$SOURCE_SHA\"",
		"mount -o remount,bind,ro,nosuid,nodev \"$source_root\"",
		"mount -o remount,bind,ro,nosuid,nodev \"$controller_root\"",
		"test ! -w \"$source_root/go.mod\"",
		"test ! -w \"$controller_root/envelopes/$ENVELOPE_NAME\"",
		"go build -o \"$tools_root/synapse-callgraph\"",
		"export SYNAPSE_REACHABILITY_CONTROLLER_ENVELOPE=\"$controller_root/envelopes/$ENVELOPE_NAME\"",
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("workflow lacks immutable trusted execution custody: missing %q", required)
		}
	}

	for _, required := range []string{
		"needs: [route, benchmark, pr-lifecycle, go-oss-baselines, python-oss-baselines]",
		"EVENT_NAME: ${{ github.event_name }}",
		`if [ "$EVENT_NAME" = pull_request ]; then`,
		`test "$TRUSTED" = false`,
		`test "$BENCHMARK" = skipped`,
		`test "$PR_LIFECYCLE" = success`,
		`test -n "$PR_ARTIFACT"`,
		`test "$TRUSTED" = true`,
		`test "$BENCHMARK" = success`,
		`test -n "$BENCHMARK_ARTIFACT"`,
		`test "$PR_LIFECYCLE" = skipped`,
		`test "$GO_BASELINE" = success`,
		`test -n "$GO_ARTIFACT"`,
		`test "$PYTHON_BASELINE" = success`,
		`test -n "$PYTHON_ARTIFACT"`,
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("workflow aggregate does not enforce the event truth table: missing %q", required)
		}
	}

	teardown := strings.Index(workflow, "- name: Teardown trusted benchmark workspace")
	if teardown < 0 || !strings.Contains(workflow[teardown:], "if: ${{ always() }}") || !strings.Contains(workflow[teardown:], "\"$RUNNER_TEMP/synapse-reachability-private-runtime\"") {
		t.Fatal("workflow teardown must always remove isolated trusted runtime state")
	}
	if strings.Contains(workflow, "fetch-depth: 1") || strings.Contains(workflow, "git fetch --no-tags --depth=1") {
		t.Fatal("workflow must retain complete trusted ancestry for baseline identity checks")
	}
}

func TestReachabilityBenchmarkMakeTargetPolicy(t *testing.T) {
	makefile := readReachabilityBenchmarkFile(t, "Makefile")
	target := regexp.MustCompile(`(?m)^reachability-benchmark:[^\n]*(?:\n\t[^\n]*)*`).FindString(makefile)
	if target == "" {
		t.Fatal("Makefile must retain the reachability benchmark target")
	}
	normalizedTarget := strings.ReplaceAll(target, "\t", "")

	for _, required := range []string{
		`tools_root=""; \`,
		`trap cleanup EXIT; \`,
		`trap 'exit 1' HUP INT TERM; \`,
		`tools_root="$$(mktemp -d "$${TMPDIR:-/tmp}/synapse-reachability-tools.XXXXXX")"; \`,
		`chmod 0700 -- "$$tools_root"; \`,
		`export SYNAPSE_JSREACH_TIER2_ENABLED=true; \`,
		`export SYNAPSE_JVM_REACH_TIER2_POINTS_TO_ENABLED=true; \`,
		`$(GO) run ./cmd/synapse-reachability-cycle`,
	} {
		if !strings.Contains(normalizedTarget, required) {
			t.Fatalf("reachability benchmark target is not self-contained: missing %q", required)
		}
	}

	const lifecycleCommand = `$(GO) run ./cmd/synapse-reachability-cycle`
	if strings.Count(normalizedTarget, lifecycleCommand) != 1 || !regexp.MustCompile(`(?m)^\$\(GO\) run \./cmd/synapse-reachability-cycle$`).MatchString(normalizedTarget) {
		t.Fatal("reachability benchmark target must invoke the lifecycle with no arguments exactly once")
	}

	for _, helper := range []string{
		`if [ -z "$${SYNAPSE_TAINT_CALLGRAPH_BIN:-}" ]; then \
$(GO) build -o "$$tools_root/synapse-callgraph" ./cmd/synapse-callgraph; \
test -x "$$tools_root/synapse-callgraph"; \
export SYNAPSE_TAINT_CALLGRAPH_BIN="$$tools_root/synapse-callgraph"; \
fi; \`,
		`if [ -z "$${SYNAPSE_AST_BIN:-}" ]; then \
$(GO) build -o "$$tools_root/synapse-ast" ./cmd/synapse-ast; \
test -x "$$tools_root/synapse-ast"; \
export SYNAPSE_AST_BIN="$$tools_root/synapse-ast"; \
fi; \`,
	} {
		if !strings.Contains(normalizedTarget, helper) {
			t.Fatalf("reachability benchmark target must preserve a supplied helper path: missing %q", helper)
		}
	}
}

func readReachabilityBenchmarkWorkflow(t *testing.T) string {
	return readReachabilityBenchmarkFile(t, ".github", "workflows", "reachability-benchmark.yml")
}

func readReachabilityBenchmarkFile(t *testing.T, relativePath ...string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate reachability benchmark policy test source")
	}
	path := filepath.Join(append([]string{filepath.Dir(thisFile), "..", "..", ".."}, relativePath...)...)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read reachability benchmark policy file: %v", err)
	}
	return strings.ReplaceAll(string(content), "\r\n", "\n")
}
