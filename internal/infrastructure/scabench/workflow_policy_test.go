package scabench

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEngineAccuracyWorkflowPolicy(t *testing.T) {
	workflow := readEngineAccuracyWorkflow(t)

	for _, required := range []string{
		`if [ "$EVENT_NAME" != pull_request ] && [ "$ENABLED" = true ] && [ -n "$TRUSTED_SHA" ] && [ "$REF" = "${TRUSTED_REF:-refs/heads/main}" ] && [ "$SHA" = "$TRUSTED_SHA" ]; then`,
		"if: ${{ needs.route.outputs.trusted == 'true' }}",
		"runs-on: [self-hosted, linux, sca-accuracy-trusted]",
		`if [ "$EVENT_NAME" = pull_request ]; then`,
		`test "$TRUSTED" = false`,
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("workflow must retain trusted-route guard %q", required)
		}
	}

	const trustedEnvironment = "environment: trusted-benchmarks"
	benchmarkStart := strings.Index(workflow, "\n  benchmark:\n")
	benchmarkEnd := strings.Index(workflow, "\n  aggregate:\n")
	if benchmarkStart < 0 || benchmarkEnd <= benchmarkStart {
		t.Fatal("workflow must retain the trusted benchmark job before aggregate")
	}
	if got := strings.Count(workflow, trustedEnvironment); got != 1 {
		t.Fatalf("workflow must declare the trusted environment exactly once: got %d", got)
	}
	if !strings.Contains(workflow[benchmarkStart:benchmarkEnd], "\n    "+trustedEnvironment+"\n") {
		t.Fatal("trusted benchmark job must declare the trusted environment")
	}
	if strings.Contains(workflow[:benchmarkStart], trustedEnvironment) || strings.Contains(workflow[benchmarkEnd:], trustedEnvironment) {
		t.Fatal("only the self-hosted trusted benchmark job may declare the trusted environment")
	}
}

func readEngineAccuracyWorkflow(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate engine accuracy workflow policy test source")
	}
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", ".github", "workflows", "engine-accuracy.yml")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read engine accuracy workflow: %v", err)
	}
	return strings.ReplaceAll(string(content), "\r\n", "\n")
}
