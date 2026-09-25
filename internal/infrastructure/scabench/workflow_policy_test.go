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
		"uses: aws-actions/configure-aws-credentials@a03048d87541d1d9fcf2ecf528a4a65ba9bd7838",
		"--document synapse-sca-trusted-20260925",
		"--instance-id i-0c53bf1e69ea15698",
		"scripts/verify_sca_maintainer_authorization.py capture",
		"scripts/dispatch_sca_trusted_ssm.py dispatch",
		`if [ "$EVENT_NAME" = pull_request ]; then`,
		`test "$TRUSTED" = false`,
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("workflow must retain trusted-route guard %q", required)
		}
	}

	const trustedEnvironment = "environment: trusted-benchmarks"
	provenanceStart := strings.Index(workflow, "\n  provenance:\n")
	benchmarkStart := strings.Index(workflow, "\n  benchmark:\n")
	benchmarkEnd := strings.Index(workflow, "\n  aggregate:\n")
	if provenanceStart < 0 || benchmarkStart <= provenanceStart || benchmarkEnd <= benchmarkStart {
		t.Fatal("workflow must retain hosted provenance and trusted benchmark jobs before aggregate")
	}
	if got := strings.Count(workflow, trustedEnvironment); got != 2 {
		t.Fatalf("workflow must declare the trusted environment for provenance and benchmark: got %d", got)
	}
	if !strings.Contains(workflow[benchmarkStart:benchmarkEnd], "\n    "+trustedEnvironment+"\n") {
		t.Fatal("trusted benchmark job must declare the trusted environment")
	}
	if !strings.Contains(workflow[provenanceStart:benchmarkStart], "\n    "+trustedEnvironment+"\n") {
		t.Fatal("hosted provenance job must declare the trusted environment")
	}
	if strings.Contains(workflow[:provenanceStart], trustedEnvironment) || strings.Contains(workflow[benchmarkEnd:], trustedEnvironment) {
		t.Fatal("trusted environment may only gate provenance and benchmark jobs")
	}
	if strings.Contains(workflow, "self-hosted") || strings.Contains(workflow, "sca-accuracy-trusted") {
		t.Fatal("public repository workflow must not schedule the trusted VM as a self-hosted runner")
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
