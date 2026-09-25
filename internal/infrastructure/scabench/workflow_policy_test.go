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
		"pull_request:\n    branches: [main]",
		"push:\n    branches: [main]",
		"schedule:",
		"workflow_dispatch:",
		"runs-on: ubuntu-latest",
		"-mode sca-owned",
		"TestDetectionAccuracyGolden",
		"verify_sca_hosted_regression.py",
		"accepted-capture.json",
		"extract_sca_hosted_inputs.py",
		"hosted-owned-inputs.tar.gz",
		"--owned-helper",
		"sca_hosted_score.go",
		`jq -e '.passed == true and .target_count == 3'`,
		"if-no-files-found: error",
		"needs: regression",
		`test "$REGRESSION" = success`,
		`test -n "$ARTIFACT"`,
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("hosted regression workflow lacks %q", required)
		}
	}
	for _, forbidden := range []string{"trusted-benchmarks", "self-hosted", "if: ${{ needs.route.outputs.trusted", "skipped"} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("hosted regression must not depend on %q", forbidden)
		}
	}
	audit := readEngineAccuracyWorkflowFile(t, "engine-accuracy-audit.yml")
	if !strings.Contains(audit, "on:\n  workflow_dispatch:\n") || strings.Contains(audit, "on:\n  pull_request:") || strings.Contains(audit, "on:\n  push:") {
		t.Fatal("evidence capture must be manual")
	}
	if !strings.Contains(audit, "environment: trusted-benchmarks") || !strings.Contains(audit, "scripts/dispatch_sca_trusted_ssm.py dispatch") || !strings.Contains(audit, `test "$TRUSTED" = true`) {
		t.Fatal("manual audit must retain its guarded SSM capture")
	}
}

func readEngineAccuracyWorkflow(t *testing.T) string {
	return readEngineAccuracyWorkflowFile(t, "engine-accuracy.yml")
}

func readEngineAccuracyWorkflowFile(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate engine accuracy workflow policy test source")
	}
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", ".github", "workflows", name)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read engine accuracy workflow: %v", err)
	}
	return strings.ReplaceAll(string(content), "\r\n", "\n")
}
