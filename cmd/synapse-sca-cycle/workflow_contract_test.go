package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestEngineAccuracyWorkflowSafetyContract(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve workflow path")
	}
	workflowPath := filepath.Join(filepath.Dir(source), "..", "..", ".github", "workflows", "engine-accuracy.yml")
	body, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatal(err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(body, &document); err != nil {
		t.Fatalf("parse workflow YAML: %v", err)
	}
	root := yamlDocumentMapping(t, &document)

	trigger := yamlMappingValue(t, root, "on")
	for _, name := range []string{"pull_request", "push", "schedule", "workflow_dispatch"} {
		if yamlMappingValue(t, trigger, name) == nil {
			t.Errorf("workflow trigger %q is missing", name)
		}
	}
	if yamlMappingValue(t, trigger, "pull_request_target") != nil {
		t.Error("workflow must not use pull_request_target")
	}
	push := yamlMappingValue(t, trigger, "push")
	if got := yamlSequenceScalars(t, yamlMappingValue(t, push, "branches")); !sameStrings(got, []string{"**"}) {
		t.Errorf("push branches = %v, want reusable all-branch candidate trigger", got)
	}
	for _, forbidden := range []string{"paths", "paths-ignore"} {
		if yamlMappingValue(t, trigger, forbidden) != nil {
			t.Errorf("workflow must not use top-level %q filtering", forbidden)
		}
	}
	permissions := yamlMappingValue(t, root, "permissions")
	if got := yamlScalar(t, yamlMappingValue(t, permissions, "contents")); got != "read" {
		t.Errorf("contents permission = %q, want read", got)
	}

	jobs := yamlMappingValue(t, root, "jobs")
	changes := yamlMappingValue(t, jobs, "changes")
	if got := yamlScalar(t, yamlMappingValue(t, workflowStep(t, workflowSteps(t, changes), "Check out exact source revision"), "uses")); got != "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" {
		t.Errorf("changes checkout action = %q", got)
	}
	if got := yamlScalar(t, yamlMappingValue(t, yamlMappingValue(t, changes, "outputs"), "trusted_requested")); got != "${{ steps.classify.outputs.trusted_requested }}" {
		t.Errorf("trusted-request output = %q", got)
	}
	classify := workflowStep(t, workflowSteps(t, changes), "Classify changed surface")
	classifyEnvironment := yamlMappingValue(t, classify, "env")
	for key, want := range map[string]string{
		"EVENT_NAME":      "${{ github.event_name }}",
		"WORKFLOW_REF":    "${{ github.ref }}",
		"TRUSTED_ENABLED": "${{ vars.ENGINE_ACCURACY_TRUSTED_ENABLED }}",
		"TRUSTED_REF":     "${{ vars.ENGINE_ACCURACY_TRUSTED_REF }}",
	} {
		if got := yamlScalar(t, yamlMappingValue(t, classifyEnvironment, key)); got != want {
			t.Errorf("classify environment %s = %q, want %q", key, got, want)
		}
	}
	classifyRun := yamlScalar(t, yamlMappingValue(t, classify, "run"))
	for _, required := range []string{"trusted_requested=false", "refs/heads/main", "$TRUSTED_REF", "$WORKFLOW_REF", "trusted_requested=$trusted_requested"} {
		if !strings.Contains(classifyRun, required) {
			t.Errorf("trusted-request classifier is missing %q", required)
		}
	}
	trusted := yamlMappingValue(t, jobs, "trusted-full")
	if condition := yamlScalar(t, yamlMappingValue(t, trusted, "if")); condition != "${{ needs.changes.outputs.trusted_requested == 'true' }}" {
		t.Errorf("trusted cycle condition = %q, want exact classified request gate", condition)
	}
	if got := yamlSequenceScalars(t, yamlMappingValue(t, trusted, "runs-on")); !sameStrings(got, []string{"self-hosted", "linux", "sca-accuracy-trusted"}) {
		t.Errorf("trusted runner labels = %v", got)
	}
	if got := yamlScalar(t, yamlMappingValue(t, trusted, "timeout-minutes")); got != "45" {
		t.Errorf("trusted cycle timeout = %q, want 45", got)
	}

	steps := workflowSteps(t, trusted)
	setupGo := workflowStep(t, steps, "Set up Go")
	if got := yamlScalar(t, yamlMappingValue(t, setupGo, "uses")); got != "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e" {
		t.Errorf("trusted Go setup action = %q", got)
	}
	if got := yamlScalar(t, yamlMappingValue(t, yamlMappingValue(t, setupGo, "with"), "go-version-file")); got != "go.mod" {
		t.Errorf("trusted Go setup version source = %q", got)
	}
	initializeAuditControls := workflowStep(t, steps, "Initialize audit-safe capture controls")
	initializeAuditRun := yamlScalar(t, yamlMappingValue(t, initializeAuditControls, "run"))
	for _, required := range []string{"mkdir -p \"$output/control\" \"$output/records\"", "capture-status.json", "preflight_pending", "accepted-bundles.json"} {
		if !strings.Contains(initializeAuditRun, required) {
			t.Errorf("audit control initialization is missing %q", required)
		}
	}
	if workflowStepIndex(t, steps, "Initialize audit-safe capture controls") >= workflowStepIndex(t, steps, "Set up Go") {
		t.Error("audit control initialization must precede setup-go")
	}
	preflight := workflowStep(t, steps, "Preflight exact trusted runner contract")
	preflightRun := yamlScalar(t, yamlMappingValue(t, preflight, "run"))
	for _, required := range []string{"bwrap", "SCA_ACCURACY_DELEGATED_CGROUP_ROOT", "SCA_ACCURACY_RAW_RETENTION_ROOT", "syft-probe.json", "syft-config.json", "SCA_ACCURACY_SYFT_CONFIG_DIGEST", "sboms/$target_id.cdx.json", "jq -S -c", "cmp -s", "expected_components", "actual_components", "preflight_complete"} {
		if !strings.Contains(preflightRun, required) {
			t.Errorf("trusted preflight is missing %q", required)
		}
	}
	if strings.Contains(preflightRun, "syft version") || strings.Contains(preflightRun, "syft ") {
		t.Error("trusted evaluation must verify frozen Syft provenance without invoking Syft")
	}

	freeze := workflowStep(t, steps, "Generate scanner-free source and native evidence, then freeze the oracle chain")
	freezeRun := yamlScalar(t, yamlMappingValue(t, freeze, "run"))
	for _, required := range []string{"$input/sboms/$target_id.cdx.json", "cp \"$frozen_sbom\" \"$sbom\"", "cmp -s \"$frozen_sbom\" \"$sbom\"", "oracle-candidate", "oracle-cross-check", "oracle-adjudicate", "oracle-freeze", "sca-accuracy-prepare", "source_evidence_preparing", "capture_pending"} {
		if !strings.Contains(freezeRun, required) {
			t.Errorf("frozen-source step is missing %q", required)
		}
	}
	if strings.Contains(freezeRun, "syft ") {
		t.Error("frozen-source step regenerated an SBOM")
	}

	capture := workflowStep(t, steps, "Capture planned slots with retained retries")
	if got := yamlScalar(t, yamlMappingValue(t, capture, "id")); got != "capture" {
		t.Errorf("capture step id = %q, want capture", got)
	}
	captureRun := yamlScalar(t, yamlMappingValue(t, capture, "run"))
	for _, required := range []string{"for repetition in 1 2", "for attempt in 1 2 3", "case \"$exit_code\" in", "2)", "test -s \"$record\"", "test -d \"$bundle\"", "retained_failed_attempts", "accepted_slots", "pre_dispatch_failure", "capture_failed", "accepted-bundles.json", "attempt:$attempt", "per_repetition_dispatches", "per_repetition_unsupported", "expected_dispatches", "expected_unsupported", "test \"$expected_slots\" = 16", "test \"$expected_dispatches\" = 14", "test \"$expected_unsupported\" = 2", "-mode ledger"} {
		if !strings.Contains(captureRun, required) {
			t.Errorf("capture step is missing %q", required)
		}
	}
	if strings.Contains(captureRun, "continue-on-error") {
		t.Error("capture step must preserve attempt status rather than masking it")
	}
	if strings.Contains(captureRun, "sles-15-6-bci-base-amd64") {
		t.Error("capture counts must derive unsupported slots from the plan, not a target name")
	}

	auditUpload := workflowStep(t, steps, "Upload audited capture controls before verdict")
	if got := yamlScalar(t, yamlMappingValue(t, auditUpload, "if")); got != "${{ always() }}" {
		t.Errorf("audit upload condition = %q, want always", got)
	}
	if got := yamlScalar(t, yamlMappingValue(t, auditUpload, "uses")); got != "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" {
		t.Errorf("audit upload action = %q", got)
	}
	auditWith := yamlMappingValue(t, auditUpload, "with")
	for _, required := range []string{"sca-accuracy-candidate/control", "sca-accuracy-candidate/records", "sca-accuracy-candidate/capture-status.json"} {
		if !strings.Contains(yamlScalar(t, yamlMappingValue(t, auditWith, "path")), required) {
			t.Errorf("audit upload misses %q", required)
		}
	}
	if got := yamlScalar(t, yamlMappingValue(t, auditWith, "name")); !strings.Contains(got, "${{ github.run_id }}-${{ github.run_attempt }}") {
		t.Errorf("audit artifact name lacks run identity: %q", got)
	}
	if got := yamlScalar(t, yamlMappingValue(t, auditWith, "if-no-files-found")); got != "error" {
		t.Errorf("audit artifact file policy = %q, want error", got)
	}
	if strings.Contains(yamlScalar(t, yamlMappingValue(t, auditWith, "path")), "SCA_ACCURACY_RAW_RETENTION_ROOT") {
		t.Error("audit artifact upload must not expose protected raw retention")
	}
	finalize := workflowStep(t, steps, "Finalize comparisons, falsifiers, reduction, ratchet, and report")
	if got := yamlScalar(t, yamlMappingValue(t, finalize, "if")); got != "${{ steps.capture.outputs.accepted == 'true' }}" {
		t.Errorf("finalize condition = %q", got)
	}
	failure := workflowStep(t, steps, "Fail after audited retained-attempt upload")
	if !strings.Contains(yamlScalar(t, yamlMappingValue(t, failure, "if")), "steps.capture.outputs.accepted != 'true'") {
		t.Error("failure verdict does not follow the audit upload and retained-attempt result")
	}
	finalizeRun := yamlScalar(t, yamlMappingValue(t, finalize, "run"))
	for _, required := range []string{"accepted-bundles.json", "attempt-$attempt", "attempt-$second_attempt", "missing or ambiguous accepted bundle"} {
		if !strings.Contains(finalizeRun, required) {
			t.Errorf("finalization does not resolve accepted retry bundles through %q", required)
		}
	}
	candidateUpload := workflowStep(t, steps, "Upload bounded candidate controls and results")
	candidateWith := yamlMappingValue(t, candidateUpload, "with")
	if got := yamlScalar(t, yamlMappingValue(t, candidateWith, "name")); !strings.Contains(got, "${{ github.run_id }}-${{ github.run_attempt }}") {
		t.Errorf("candidate artifact name lacks run identity: %q", got)
	}

	aggregate := yamlMappingValue(t, jobs, "aggregate")
	aggregateStep := workflowStep(t, workflowSteps(t, aggregate), "Require every applicable outcome and full artifact production")
	aggregateEnvironment := yamlMappingValue(t, aggregateStep, "env")
	if got := yamlScalar(t, yamlMappingValue(t, aggregateEnvironment, "TRUSTED_REQUESTED")); got != "${{ needs.changes.outputs.trusted_requested }}" {
		t.Errorf("aggregate trusted-request environment = %q", got)
	}
	aggregateRun := yamlScalar(t, yamlMappingValue(t, aggregateStep, "run"))
	for _, required := range []string{"$TRUSTED_REQUESTED", "$TRUSTED_ENABLED", "non-authorized ref", "$WORKFLOW_REF"} {
		if !strings.Contains(aggregateRun, required) {
			t.Errorf("aggregate does not record explicit unrequested trusted evidence for %q", required)
		}
	}
	assertNoWorkflowKey(t, root, "continue-on-error")
}

func TestSCAAccuracyPublicationMakefileInputsAreDeclared(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve Makefile path")
	}
	makefilePath := filepath.Join(filepath.Dir(source), "..", "..", "Makefile")
	body, err := os.ReadFile(makefilePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range []string{
		"SCA_ACCURACY_PUBLICATION_CONTROL ?=",
		"SCA_ACCURACY_PUBLICATION_OUTPUT ?=",
	} {
		found := false
		for _, line := range strings.Split(string(body), "\n") {
			if strings.TrimSpace(line) == declaration {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Makefile declaration %q is missing", declaration)
		}
	}
}

func yamlDocumentMapping(t *testing.T, document *yaml.Node) *yaml.Node {
	t.Helper()
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		t.Fatal("workflow root must be a mapping document")
	}
	return document.Content[0]
}

func yamlMappingValue(t *testing.T, mapping *yaml.Node, key string) *yaml.Node {
	t.Helper()
	if mapping == nil {
		return nil
	}
	if mapping.Kind != yaml.MappingNode {
		t.Fatalf("expected mapping while looking up %q, got kind %d", key, mapping.Kind)
	}
	for index := 0; index < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			return mapping.Content[index+1]
		}
	}
	return nil
}

func yamlScalar(t *testing.T, node *yaml.Node) string {
	t.Helper()
	if node == nil {
		return ""
	}
	if node.Kind != yaml.ScalarNode {
		t.Fatalf("expected scalar node, got kind %d", node.Kind)
	}
	return node.Value
}

func yamlSequenceScalars(t *testing.T, node *yaml.Node) []string {
	t.Helper()
	if node == nil || node.Kind != yaml.SequenceNode {
		t.Fatal("expected sequence node")
	}
	values := make([]string, 0, len(node.Content))
	for _, item := range node.Content {
		values = append(values, yamlScalar(t, item))
	}
	return values
}

func workflowSteps(t *testing.T, job *yaml.Node) []*yaml.Node {
	t.Helper()
	steps := yamlMappingValue(t, job, "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode {
		t.Fatal("workflow job requires a steps sequence")
	}
	return steps.Content
}

func workflowStep(t *testing.T, steps []*yaml.Node, name string) *yaml.Node {
	t.Helper()
	for _, step := range steps {
		if yamlScalar(t, yamlMappingValue(t, step, "name")) == name {
			return step
		}
	}
	t.Fatalf("workflow step %q is missing", name)
	return nil
}

func workflowStepIndex(t *testing.T, steps []*yaml.Node, name string) int {
	t.Helper()
	for index, step := range steps {
		if yamlScalar(t, yamlMappingValue(t, step, "name")) == name {
			return index
		}
	}
	t.Fatalf("workflow step %q is missing", name)
	return -1
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func assertNoWorkflowKey(t *testing.T, node *yaml.Node, key string) {
	t.Helper()
	if node == nil {
		return
	}
	if node.Kind == yaml.MappingNode {
		for index := 0; index < len(node.Content); index += 2 {
			if node.Content[index].Value == key {
				t.Errorf("workflow contains forbidden key %q", key)
			}
			assertNoWorkflowKey(t, node.Content[index+1], key)
		}
		return
	}
	for _, child := range node.Content {
		assertNoWorkflowKey(t, child, key)
	}
}
