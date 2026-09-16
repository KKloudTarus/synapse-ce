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
	workflowText := string(body)
	for _, forbidden := range []string{
		"base_sha", "evidence_only", "full_required",
		"internal/usecase/scabench/testdata/publication/publication-manifest.json",
		"$input/source-freeze.json", "$input/source-evidence-plan.json", "$input/accountable-review.json", "$input/plan.json", "$input/publication-control.json",
		"for repetition in 1 2", "for attempt in 1 2 3", ".repetition == 2",
		"test \"$expected_slots\" = 16", "test \"$expected_dispatches\" = 14", "test \"$expected_unsupported\" = 2",
	} {
		if strings.Contains(workflowText, forbidden) {
			t.Errorf("workflow retains manual or checked-in evidence control %q", forbidden)
		}
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
	classify := workflowStep(t, workflowSteps(t, changes), "Classify trusted execution request")
	classifyEnvironment := yamlMappingValue(t, classify, "env")
	for key, want := range map[string]string{
		"EVENT_NAME":      "${{ github.event_name }}",
		"WORKFLOW_REF":    "${{ github.ref }}",
		"WORKFLOW_SHA":    "${{ steps.resolve.outputs.source_sha }}",
		"TRUSTED_ENABLED": "${{ vars.ENGINE_ACCURACY_TRUSTED_ENABLED }}",
		"TRUSTED_REF":     "${{ vars.ENGINE_ACCURACY_TRUSTED_REF }}",
		"TRUSTED_SHA":     "${{ vars.ENGINE_ACCURACY_TRUSTED_SHA }}",
	} {
		if got := yamlScalar(t, yamlMappingValue(t, classifyEnvironment, key)); got != want {
			t.Errorf("classify environment %s = %q, want %q", key, got, want)
		}
	}
	classifyRun := yamlScalar(t, yamlMappingValue(t, classify, "run"))
	for _, required := range []string{"trusted_requested=false", "refs/heads/main", "${TRUSTED_REF:-refs/heads/main}", "$WORKFLOW_REF", "$WORKFLOW_SHA", "$TRUSTED_SHA", "[ -n \"$TRUSTED_SHA\" ]", "[ \"$WORKFLOW_REF\" = \"$trusted_ref\" ]", "[ \"$WORKFLOW_SHA\" = \"$TRUSTED_SHA\" ]", "trusted_requested=$trusted_requested"} {
		if !strings.Contains(classifyRun, required) {
			t.Errorf("trusted-request classifier is missing %q", required)
		}
	}
	offline := yamlMappingValue(t, jobs, "offline-verify")
	if condition := yamlScalar(t, yamlMappingValue(t, offline, "if")); condition != "${{ github.event_name == 'pull_request' }}" {
		t.Errorf("offline verification condition = %q, want pull-request only", condition)
	}
	if run := yamlScalar(t, yamlMappingValue(t, workflowStep(t, workflowSteps(t, offline), "Verify benchmark contract without scanners"), "run")); run != "make sca-accuracy-verify" {
		t.Errorf("offline verification command = %q", run)
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
	trustedOutputs := yamlMappingValue(t, trusted, "outputs")
	for key, want := range map[string]string{
		"artifacts":       "${{ steps.complete.outputs.artifacts }}",
		"artifact_id":     "${{ steps.candidate-upload.outputs.artifact-id }}",
		"artifact_url":    "${{ steps.candidate-upload.outputs.artifact-url }}",
		"artifact_digest": "${{ steps.candidate-upload.outputs.artifact-digest }}",
		"artifact_name":   "${{ steps.complete.outputs.artifact_name }}",
	} {
		if got := yamlScalar(t, yamlMappingValue(t, trustedOutputs, key)); got != want {
			t.Errorf("trusted output %s = %q, want %q", key, got, want)
		}
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
	for _, required := range []string{"command -v jq", "cycle-policy.json", "capture-status.json", "preflight_pending", "accepted-bundles.json", "repetitions=", "max_attempts=", "accepted_retention_days=", "failed_retention_days="} {
		if !strings.Contains(initializeAuditRun, required) {
			t.Errorf("audit control initialization is missing %q", required)
		}
	}
	if strings.Index(initializeAuditRun, "command -v jq") > strings.Index(initializeAuditRun, "jq -er") {
		t.Error("audit control initialization must assert jq availability before reading policy")
	}
	if workflowStepIndex(t, steps, "Initialize audit-safe capture controls") >= workflowStepIndex(t, steps, "Set up Go") {
		t.Error("audit control initialization must precede setup-go")
	}
	preflight := workflowStep(t, steps, "Preflight exact trusted runner contract")
	preflightRun := yamlScalar(t, yamlMappingValue(t, preflight, "run"))
	for _, required := range []string{
		"bwrap", "SCA_ACCURACY_DELEGATED_CGROUP_ROOT", "SCA_ACCURACY_RAW_RETENTION_ROOT",
		"SCA_ACCURACY_ACTIONS_RUNNER_ROOT", "$runner_root/.runner", "command -v jq", ".ephemeral == true", "runner_config_digest",
		"syft-probe.json", "syft-config.json", "SCA_ACCURACY_SYFT_CONFIG_DIGEST", "ratchet-baseline.json",
		"sboms/$target_id.cdx.json", "jq -S -c", "cmp -s", "expected_components", "actual_components",
		"reviews/github", "reviews/dispositions/github", "review_files", "decision_files",
		`.state == "COMMENTED" or .state == "APPROVED"`,
		`implementation_commit="${{ needs.changes.outputs.source_sha }}"`,
		".implementation_commit == $implementation_commit", ".created_at == .updated_at",
		`test "$decision_login" != "$review_login"`, "preflight_complete",
	} {
		if !strings.Contains(preflightRun, required) {
			t.Errorf("trusted preflight is missing %q", required)
		}
	}
	if strings.Contains(preflightRun, "CHANGES_REQUESTED") {
		t.Error("trusted preflight must whitelist accepted review states rather than override changes requested")
	}
	if strings.Index(preflightRun, "command -v jq") > strings.Index(preflightRun, ".ephemeral == true") {
		t.Error("trusted preflight must assert jq availability before runner attestation")
	}
	if strings.Contains(preflightRun, "syft version") || strings.Contains(preflightRun, "syft ") {
		t.Error("trusted evaluation must verify frozen Syft provenance without invoking Syft")
	}

	freeze := workflowStep(t, steps, "Materialize inputs and freeze the scanner-free oracle chain")
	freezeRun := yamlScalar(t, yamlMappingValue(t, freeze, "run"))
	for _, required := range []string{
		"-mode source-freeze", "-mode manifest-set", "-mode accountable-review", "-review-capture-output", "-decision-capture-output", "-implementation-commit", "-mode plan", "-baseline-ratchet",
		"control/ratchet-baseline.json", "control/review-disposition-capture.json",
		"control/source-assets", "-repository-root \"$input/repository\" -source-freeze-output", "$input/sboms/$target_id.cdx.json", "cp \"$frozen_sbom\" \"$sbom\"", "cmp -s \"$frozen_sbom\" \"$sbom\"",
		"sca-accuracy-source-native-evidence", "oracle-candidate", "oracle-cross-check", "oracle-adjudicate", "oracle-freeze", "sca-accuracy-prepare",
		"source_evidence_preparing", "capture_pending",
	} {
		if !strings.Contains(freezeRun, required) {
			t.Errorf("materialization step is missing %q", required)
		}
	}
	for _, forbidden := range []string{"target_ref=", "target_digest=", "RepoDigests", "docker image inspect", "syft "} {
		if strings.Contains(freezeRun, forbidden) {
			t.Errorf("materialization step retains live or tag-sensitive input generation %q", forbidden)
		}
	}

	capture := workflowStep(t, steps, "Capture planned slots with retained retries")
	if got := yamlScalar(t, yamlMappingValue(t, capture, "id")); got != "capture" {
		t.Errorf("capture step id = %q, want capture", got)
	}
	captureRun := yamlScalar(t, yamlMappingValue(t, capture, "run"))
	for _, required := range []string{
		"repetitions=\"$(jq -er '.repetitions'", "max_attempts=\"$(jq -er '.max_attempts'", "retention_policy=\"$(jq -er '.raw_retention'",
		"while [ \"$repetition\" -le \"$repetitions\" ]", "while [ \"$attempt\" -le \"$max_attempts\" ]", "case \"$exit_code\" in", "2)",
		"test -s \"$record\"", "test -d \"$bundle\"", "retained_failed_attempts", "accepted_slots", "pre_dispatch_failure", "capture_failed",
		"accepted-bundles.json", "attempt:$attempt", "per_repetition_dispatches", "per_repetition_unsupported", "expected_dispatches", "expected_unsupported", "-mode ledger",
	} {
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
	if got := yamlScalar(t, yamlMappingValue(t, auditWith, "retention-days")); got != "${{ steps.policy.outputs.failed_retention_days }}" {
		t.Errorf("audit artifact retention = %q, want policy-derived value", got)
	}
	if strings.Contains(yamlScalar(t, yamlMappingValue(t, auditWith, "path")), "SCA_ACCURACY_RAW_RETENTION_ROOT") {
		t.Error("audit artifact upload must not expose protected raw retention")
	}

	finalize := workflowStep(t, steps, "Finalize comparisons, falsifiers, reduction, ratchet, and report")
	if got := yamlScalar(t, yamlMappingValue(t, finalize, "if")); got != "${{ steps.capture.outputs.accepted == 'true' }}" {
		t.Errorf("finalize condition = %q", got)
	}
	finalizeRun := yamlScalar(t, yamlMappingValue(t, finalize, "run"))
	for _, required := range []string{
		"accepted-bundles.json", "control/observations", "comparison_repetition=\"$repetitions\"", "attempt-$attempt", "attempt-$second_attempt", "missing or ambiguous accepted bundle",
		"publication/source-case-evidence.json", "publication/native-evidence.json", "-mode publication-control", "sca-accuracy-publication",
		"rm -f \\", "for transient in \\", "control/publication-control.json",
	} {
		if !strings.Contains(finalizeRun, required) {
			t.Errorf("finalization is missing %q", required)
		}
	}

	cleanup := workflowStep(t, steps, "Clean protected raw and Docker runner state")
	if got := yamlScalar(t, yamlMappingValue(t, cleanup, "if")); got != "${{ always() }}" {
		t.Errorf("cleanup condition = %q, want always", got)
	}
	cleanupRun := yamlScalar(t, yamlMappingValue(t, cleanup, "run"))
	for _, required := range []string{"-mode cleanup", "SCA_ACCURACY_RAW_RETENTION_ROOT", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "cleanup-receipt.json"} {
		if !strings.Contains(cleanupRun, required) {
			t.Errorf("cleanup step is missing %q", required)
		}
	}
	receipt := workflowStep(t, steps, "Generate candidate inventory and delivery receipt")
	receiptRun := yamlScalar(t, yamlMappingValue(t, receipt, "run"))
	for _, required := range []string{"-mode receipt", "-implementation-commit", "-ledger \"$publication/cycle-ledger.json\"", "delivery-receipt.json", "candidate-file-inventory.json", "pr-comment.md", "artifact_name="} {
		if !strings.Contains(receiptRun, required) {
			t.Errorf("candidate receipt step is missing %q", required)
		}
	}
	candidateUpload := workflowStep(t, steps, "Upload bounded candidate controls and results")
	if got := yamlScalar(t, yamlMappingValue(t, candidateUpload, "id")); got != "candidate-upload" {
		t.Errorf("candidate upload id = %q, want candidate-upload", got)
	}
	candidateWith := yamlMappingValue(t, candidateUpload, "with")
	if got := yamlScalar(t, yamlMappingValue(t, candidateWith, "name")); got != "${{ steps.complete.outputs.artifact_name }}" {
		t.Errorf("candidate artifact name = %q, want receipt-bound output", got)
	}
	if got := yamlScalar(t, yamlMappingValue(t, candidateWith, "if-no-files-found")); got != "error" {
		t.Errorf("candidate artifact file policy = %q, want error", got)
	}
	if got := yamlScalar(t, yamlMappingValue(t, candidateWith, "retention-days")); got != "${{ steps.policy.outputs.accepted_retention_days }}" {
		t.Errorf("candidate artifact retention = %q, want policy-derived value", got)
	}
	if strings.Contains(yamlScalar(t, yamlMappingValue(t, candidateWith, "path")), "SCA_ACCURACY_RAW_RETENTION_ROOT") {
		t.Error("candidate artifact upload must not expose protected raw retention")
	}
	failure := workflowStep(t, steps, "Fail after audited retained-attempt upload")
	if !strings.Contains(yamlScalar(t, yamlMappingValue(t, failure, "if")), "steps.capture.outputs.accepted != 'true'") {
		t.Error("failure verdict does not follow the audit upload and retained-attempt result")
	}

	aggregate := yamlMappingValue(t, jobs, "aggregate")
	aggregateStep := workflowStep(t, workflowSteps(t, aggregate), "Require every applicable outcome and full artifact production")
	aggregateEnvironment := yamlMappingValue(t, aggregateStep, "env")
	if got := yamlScalar(t, yamlMappingValue(t, aggregateEnvironment, "TRUSTED_REQUESTED")); got != "${{ needs.changes.outputs.trusted_requested }}" {
		t.Errorf("aggregate trusted-request environment = %q", got)
	}
	aggregateRun := yamlScalar(t, yamlMappingValue(t, aggregateStep, "run"))
	for _, required := range []string{"$TRUSTED_REQUESTED", "$TRUSTED_ENABLED", "non-authorized ref", "$WORKFLOW_REF", "artifact_id", "artifact_digest"} {
		if !strings.Contains(aggregateRun, required) {
			t.Errorf("aggregate is missing %q", required)
		}
	}
	if strings.Contains(aggregateRun, "evidence_only") {
		t.Error("aggregate retains evidence-only routing")
	}
	assertNoWorkflowKey(t, root, "continue-on-error")
}

func TestEngineAccuracyWorkflowCatalogIdentityPreflightScopeContract(t *testing.T) {
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
	trusted := yamlMappingValue(t, yamlMappingValue(t, root, "jobs"), "trusted-full")
	preflight := workflowStep(t, workflowSteps(t, trusted), "Preflight exact trusted runner contract")
	preflightRun := yamlScalar(t, yamlMappingValue(t, preflight, "run"))

	for _, contract := range []struct {
		name     string
		required []string
	}{
		{
			name: "non-PURL components retain canonical bytes outside catalog comparison",
			required: []string{
				"jq -S -c . \"$sbom\" > \"$canonical\"",
				"cmp -s \"$sbom\" \"$canonical\"",
				"elif ((.purl? | type) == \"string\" and (.purl | trim_space | length > 0)) then",
				"else",
				"empty",
			},
		},
		{
			name: "non-target PURL scopes are excluded from catalog identity comparison",
			required: []string{
				"benchmark_scopes=\"$(jq -ce --argjson components \"$expected_components\"",
				"[$components[] | .purl | purl_scope] | unique",
				"--argjson benchmark_scopes \"$benchmark_scopes\"",
				"($benchmark_scopes | index($scope) != null)",
			},
		},
		{
			name: "extra benchmarkable PURL version components remain visible to equality",
			required: []string{
				"{purl, version}",
				"] | sort_by(.purl, .version)",
				"test \"$actual_components\" = \"$expected_components\"",
			},
		},
		{
			name: "missing benchmarkable PURL version components fail equality",
			required: []string{
				"expected_components=\"$(jq -ce --arg target \"$target_id\"",
				"[.targets[] | select(.id == $target) | .components[] |",
				"test \"$actual_components\" = \"$expected_components\"",
			},
		},
		{
			name: "malformed PURL version field types fail before comparison",
			required: []string{
				"SBOM component purl and version must be strings when present",
				"catalog component \\($field) must be a nonempty string",
			},
		},
	} {
		t.Run(contract.name, func(t *testing.T) {
			for _, required := range contract.required {
				if !strings.Contains(preflightRun, required) {
					t.Errorf("catalog identity preflight is missing %q", required)
				}
			}
		})
	}
	for _, targetID := range []string{"debian-12-13-slim-amd64", "sles-15-6-bci-base-amd64"} {
		if strings.Contains(preflightRun, targetID) {
			t.Errorf("catalog identity preflight hardcodes target %q", targetID)
		}
	}
	actualStart := strings.Index(preflightRun, "actual_components=\"$(jq")
	actualEnd := strings.Index(preflightRun, "test \"$actual_components\" = \"$expected_components\"")
	if actualStart < 0 || actualEnd <= actualStart {
		t.Fatal("locate actual catalog identity comparison")
	}
	if strings.Contains(preflightRun[actualStart:actualEnd], "unique") {
		t.Error("catalog identity comparison must preserve duplicate benchmarkable components")
	}
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
