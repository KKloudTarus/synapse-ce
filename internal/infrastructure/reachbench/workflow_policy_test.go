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
	for _, required := range []string{
		"pull_request:\n    branches: [main]",
		"push:\n    branches: [main]",
		"schedule:",
		"workflow_dispatch:",
		"runs-on: ubuntu-latest",
		"make reachability-benchmark",
		"TestGoReachabilityCorpus",
		"TestPythonReachabilityCorpus",
		"osv-go.raw.json",
		"osv-go.provenance.json",
		"sha256sum internal/usecase/reachbench/corpus/baselines/osv-go.raw.json",
		"go run ./cmd/synapse-bench -mode reachability-osv",
		"semgrep/semgrep@sha256:d39aa8d8cdb7fd9e5ec14f0825e2356f902129778c9617217856295e553254d5",
		"docker run --rm --network none --user",
		`(.errors | length) == 0 and (.results | type) == "array" and (.results | length) > 0`,
		"if-no-files-found: error",
		"needs: [route, lifecycle, go-oss-baselines, python-oss-baselines]",
		`test "$LIFECYCLE" = success`,
		`test -n "$LIFECYCLE_ARTIFACT"`,
		`test "$GO_BASELINE" = success`,
		`test -n "$GO_ARTIFACT"`,
		`test "$PYTHON_BASELINE" = success`,
		`test -n "$PYTHON_ARTIFACT"`,
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("hosted reachability workflow lacks %q", required)
		}
	}
	for _, forbidden := range []string{"self-hosted", "trusted-benchmarks", "OSV_SCANNER_VERSION", "go install github.com/google/osv-scanner", "skipped", "continue-on-error"} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("hosted regression must not depend on %q", forbidden)
		}
	}
	for _, match := range regexp.MustCompile(`(?m)^\s*uses:\s*[^@\s]+@([^\s#]+)`).FindAllStringSubmatch(workflow, -1) {
		if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(match[1]) {
			t.Fatalf("workflow action is not pinned: %q", match[0])
		}
	}
	audit := readReachabilityBenchmarkFile(t, ".github", "workflows", "reachability-audit.yml")
	if !strings.Contains(audit, "on:\n  workflow_dispatch:\n") || strings.Contains(audit, "on:\n  pull_request:") || strings.Contains(audit, "on:\n  push:") {
		t.Fatal("evidence capture must be manual")
	}
	if !strings.Contains(audit, "environment: trusted-benchmarks") || !strings.Contains(audit, "runs-on: [self-hosted, linux, reachability-accuracy-trusted]") {
		t.Fatal("manual audit must retain its guarded trusted route")
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
