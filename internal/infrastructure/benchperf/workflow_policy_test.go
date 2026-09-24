package benchperf

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const sourceSHA = "${{ needs.route.outputs.source_sha }}"

type benchmarkWorkflow struct {
	Jobs map[string]benchmarkJob `yaml:"jobs"`
}

type benchmarkJob struct {
	Needs   workflowNeeds     `yaml:"needs"`
	If      string            `yaml:"if"`
	Outputs map[string]string `yaml:"outputs"`
	Env     map[string]string `yaml:"env"`
	Steps   []benchmarkStep   `yaml:"steps"`
}

type workflowNeeds []string

func (needs *workflowNeeds) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		*needs = workflowNeeds{value.Value}
		return nil
	case yaml.SequenceNode:
		values := make(workflowNeeds, 0, len(value.Content))
		for _, entry := range value.Content {
			if entry.Kind != yaml.ScalarNode {
				return fmt.Errorf("needs entry must be a scalar")
			}
			values = append(values, entry.Value)
		}
		*needs = values
		return nil
	default:
		return fmt.Errorf("needs must be a scalar or sequence")
	}
}

type benchmarkStep struct {
	ID   string            `yaml:"id"`
	Name string            `yaml:"name"`
	Uses string            `yaml:"uses"`
	With map[string]string `yaml:"with"`
	Env  map[string]string `yaml:"env"`
	Run  string            `yaml:"run"`
}

func TestHostedBenchmarkWorkflowsBindExactSourceRevision(t *testing.T) {
	for _, tc := range []struct {
		name string
		job  string
	}{
		{name: "security-accuracy.yml", job: "accuracy"},
		{name: "dynamic-security-benchmark.yml", job: "accuracy"},
		{name: "performance-benchmark.yml", job: "measure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			workflow := readHostedBenchmarkWorkflow(t, tc.name)
			route := requireJob(t, workflow, "route")
			if route.Outputs["source_sha"] != "${{ steps.source.outputs.sha }}" {
				t.Fatal("route must expose the source SHA output")
			}
			source := requireStep(t, route, func(step benchmarkStep) bool { return step.ID == "source" })
			requireActiveLine(t, source.Run, "github.event.pull_request.head.sha || github.sha")
			requireActiveLine(t, source.Run, `[[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]`)
			requireActiveLine(t, source.Run, `echo "sha=$sha" >> "$GITHUB_OUTPUT"`)

			benchmark := requireJob(t, workflow, tc.job)
			requireNeeds(t, benchmark, "route")
			checkout := requireStep(t, benchmark, func(step benchmarkStep) bool {
				return step.Uses == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
			})
			if checkout.With["ref"] != sourceSHA {
				t.Fatalf("%s checkout must bind route source SHA, got %q", tc.job, checkout.With["ref"])
			}
			assertion := requireStep(t, benchmark, func(step benchmarkStep) bool {
				return step.Name == "Assert exact checkout revision"
			})
			requireActiveLine(t, assertion.Run, `test "$(git rev-parse HEAD)" = "${{ needs.route.outputs.source_sha }}"`)

			aggregate := requireJob(t, workflow, "aggregate")
			requireNeeds(t, aggregate, "route", tc.job)
			if aggregate.If != "${{ always() }}" {
				t.Fatalf("aggregate must always report, got if %q", aggregate.If)
			}
			aggregateStep := requireOnlyRunStep(t, aggregate)
			if aggregateStep.Env["ROUTE"] != "${{ needs.route.result }}" {
				t.Fatal("aggregate must receive route result")
			}
			requireActiveLine(t, aggregateStep.Run, `test "$ROUTE" = success`)
		})
	}
}

func TestSecurityAccuracyComparatorInputsAreImmutableAndRequired(t *testing.T) {
	workflow := readHostedBenchmarkWorkflow(t, "security-accuracy.yml")
	accuracy := requireJob(t, workflow, "accuracy")
	if accuracy.Env["GITLEAKS_LINUX_X64_SHA256"] != "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" {
		t.Fatal("Gitleaks comparison asset must use its committed SHA-256")
	}
	if accuracy.Env["CHECKOV_IMAGE"] != "bridgecrew/checkov@sha256:d3e96adafdb315ca82e792ca8708c01adae85292800fb064c8b309b3d0cb7b80" {
		t.Fatal("Checkov comparison environment must use its committed OCI digest")
	}

	gitleaks := requireStep(t, accuracy, func(step benchmarkStep) bool {
		return step.Name == "Install pinned gitleaks"
	})
	for _, want := range []string{
		`curl -fsSL --retry 3 -o "$tmp/$asset" "$base/$asset"`,
		`printf '%s  %s\n' "$GITLEAKS_LINUX_X64_SHA256" "$tmp/$asset" | sha256sum -c -`,
		`version="$(gitleaks version)"`,
		`test "$version" = "$GITLEAKS_VERSION"`,
	} {
		requireActiveLine(t, gitleaks.Run, want)
	}
	if strings.Contains(gitleaks.Run, "checksums.txt") || strings.Contains(gitleaks.Run, "skipping install") {
		t.Fatal("Gitleaks comparator must verify the committed asset digest and cannot silently skip")
	}

	checkov := requireStep(t, accuracy, func(step benchmarkStep) bool {
		return step.Name == "Install pinned checkov"
	})
	for _, want := range []string{
		`"$RUNNER_TEMP/benchmark-bin/checkov" --version`,
		`test "$version" = "$CHECKOV_VERSION"`,
		`--network none`, `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`,
		`--user "$(id -u):$(id -g)"`,
		`-v "$SYNAPSE_CHECKOV_HOST_TMPDIR:/work-tmp:ro"`, `"$SYNAPSE_CHECKOV_IMAGE"`,
		`echo "TMPDIR=$RUNNER_TEMP/benchmark-tmp"`, `} >> "$GITHUB_ENV"`,
		`export SYNAPSE_CHECKOV_HOST_TMPDIR="$RUNNER_TEMP/benchmark-tmp"`,
		`export SYNAPSE_CHECKOV_IMAGE="$CHECKOV_IMAGE"`,
	} {
		requireActiveLine(t, checkov.Run, want)
	}
	if strings.Contains(checkov.Run, "pip install") || strings.Contains(checkov.Run, "skipping") {
		t.Fatal("Checkov comparator must run from the pinned image and cannot silently skip")
	}
	for _, tc := range []struct {
		name   string
		marker string
	}{
		{"Secrets accuracy and gitleaks differential", "gitleaks secrets:"},
		{"IaC misconfiguration accuracy and checkov differential", "checkov iac:"},
	} {
		step := requireStep(t, accuracy, func(step benchmarkStep) bool { return step.Name == tc.name })
		requireActiveLine(t, step.Run, `jq -e 'select(.Action == "output"`)
		requireActiveLine(t, step.Run, `contains("`+tc.marker+`")))'`)
	}
}

func TestPerformanceBenchmarkRequiresEvidenceArtifact(t *testing.T) {
	workflow := readHostedBenchmarkWorkflow(t, "performance-benchmark.yml")
	measure := requireJob(t, workflow, "measure")
	if measure.Outputs["artifact"] != "${{ steps.upload.outputs.artifact-id }}" {
		t.Fatal("measurement job must expose the uploaded artifact ID")
	}
	upload := requireStep(t, measure, func(step benchmarkStep) bool { return step.ID == "upload" })
	if upload.Uses != "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" {
		t.Fatal("measurement evidence must use the pinned artifact action")
	}
	if !strings.Contains(upload.With["name"], sourceSHA) {
		t.Fatal("measurement evidence artifact name must bind the source SHA")
	}
	if upload.With["if-no-files-found"] != "error" {
		t.Fatal("measurement evidence upload must fail when its baseline is absent")
	}

	aggregate := requireJob(t, workflow, "aggregate")
	aggregateStep := requireOnlyRunStep(t, aggregate)
	if aggregateStep.Env["ARTIFACT"] != "${{ needs.measure.outputs.artifact }}" {
		t.Fatal("aggregate must receive the measurement artifact ID")
	}
	requireActiveLine(t, aggregateStep.Run, `test -n "$ARTIFACT"`)
}

func TestHostedBenchmarkPatternGatesRequirePassingTestEvents(t *testing.T) {
	for _, tc := range []struct {
		workflow string
		job      string
		step     string
		tests    string
		mode     string
	}{
		{"dynamic-security-benchmark.yml", "accuracy", "Passive DAST accuracy over the labeled observation corpus", "TestDASTOwnedAccuracy", "pass"},
		{"dynamic-security-benchmark.yml", "accuracy", "CSPM posture accuracy over the fixture inventory", "TestCSPMOwnedAccuracy", "pass"},
		{"security-accuracy.yml", "accuracy", "Secrets accuracy and gitleaks differential", "TestSecretsOwnedAccuracyAndGitleaksDifferential", "pass"},
		{"security-accuracy.yml", "accuracy", "IaC misconfiguration accuracy and checkov differential", "TestIaCOwnedAccuracyAndCheckovDifferential", "pass"},
		{"security-accuracy.yml", "accuracy", "Runtime host-CVE correlation accuracy", "TestHostCVECorrelationAccuracy,TestHostCVEAliasResolution", "pass"},
		{"performance-benchmark.yml", "measure", "Image extraction perf gates (small and large target classes)", "TestImageExtractPerfGate,TestImageExtractLargeImagePerfGate", "measurement"},
		{"performance-benchmark.yml", "measure", "Owned SBOM producer perf gate (pinned source class)", "TestOwnsbomPerfGate", "measurement"},
		{"performance-benchmark.yml", "measure", "OS package catalog perf gate", "TestOSPkgCatalogPerfGate", "measurement"},
		{"performance-benchmark.yml", "measure", "SBOM import perf gate (pinned SBOM class)", "TestSBOMImportPerfGate", "measurement"},
		{"performance-benchmark.yml", "measure", "Secret scan perf gate", "TestSecretScanPerfGate", "measurement"},
		{"sast-benchmark.yml", "owasp-scorecard", "Run OWASP scorecard + recall ratchet", "TestOWASPBenchmarkScorecard", "pass"},
		{"sast-benchmark.yml", "securibench-scorecard", "Run Securibench scorecard + per-CWE ratchet", "TestSecuribenchScorecard", "pass"},
		{"sast-benchmark.yml", "juliet-scorecard", "Run Juliet scorecard + per-CWE ratchet", "TestJulietScorecard", "pass"},
		{"reachability-benchmark.yml", "go-oss-baselines", "Gate owned engine recall and parity", "TestGoReachabilityCorpus", "pass"},
		{"reachability-benchmark.yml", "python-oss-baselines", "Gate owned Python engine recall and parity", "TestPythonReachabilityCorpus", "pass"},
		{"owned-default-readiness.yml", "readiness", "Owned-only default operates without Syft or Grype", "TestOwnedOnlyScanNeedsNoSyftOrGrype", "pass"},
		{"owned-default-readiness.yml", "readiness", "Unknown and unsupported coverage stays explicit", "TestOSDistroCoverageReadiness,TestOSCoverageWarnings", "pass"},
	} {
		t.Run(tc.workflow+"/"+tc.step, func(t *testing.T) {
			job := requireJob(t, readHostedBenchmarkWorkflow(t, tc.workflow), tc.job)
			step := requireStep(t, job, func(step benchmarkStep) bool { return step.Name == tc.step })
			requireActiveLine(t, step.Run, "bash scripts/require-go-tests.sh "+tc.tests)
			requireActiveLine(t, step.Run, " "+tc.mode+" ")
		})
	}
}

func TestSASTBenchmarkScorecardsBindExactSourceRevision(t *testing.T) {
	workflow := readHostedBenchmarkWorkflow(t, "sast-benchmark.yml")
	route := requireJob(t, workflow, "route")
	if route.Outputs["source_sha"] != "${{ steps.source.outputs.sha }}" {
		t.Fatal("SAST route must expose the source SHA")
	}
	source := requireStep(t, route, func(step benchmarkStep) bool { return step.ID == "source" })
	requireActiveLine(t, source.Run, `[[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]`)
	requireActiveLine(t, source.Run, `echo "sha=$sha" >> "$GITHUB_OUTPUT"`)

	for _, name := range []string{"owasp-scorecard", "securibench-scorecard", "juliet-scorecard", "adversarial-regressions"} {
		t.Run(name, func(t *testing.T) {
			job := requireJob(t, workflow, name)
			requireNeeds(t, job, "route")
			checkout := requireStep(t, job, func(step benchmarkStep) bool {
				return step.Uses == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
			})
			if checkout.With["ref"] != sourceSHA {
				t.Fatalf("scorecard checkout must bind route source SHA, got %q", checkout.With["ref"])
			}
			assertion := requireStep(t, job, func(step benchmarkStep) bool {
				return step.Name == "Assert exact checkout revision"
			})
			requireActiveLine(t, assertion.Run, `test "$(git rev-parse HEAD)" = "${{ needs.route.outputs.source_sha }}"`)
			upload := requireStep(t, job, func(step benchmarkStep) bool {
				return step.Uses == "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
			})
			if !strings.Contains(upload.With["name"], sourceSHA) || upload.With["if-no-files-found"] != "error" {
				t.Fatal("scorecard artifact must bind the source SHA and require a real log")
			}
		})
	}
	postTriage := requireJob(t, workflow, "securibench-post-triage")
	requireNeeds(t, postTriage, "route")
	if postTriage.Env["BASELINE_SOURCE_SHA"] != "ad58a4fbd0cb2096f37c2e37e79b7444ec81d230" {
		t.Fatal("post-triage baseline must pin the historical scanner revision")
	}
	for key, want := range map[string]string{
		"MODEL_ATTESTATION_SHA256":          "f23d47981610b45fabc0750197e44a348ed5000b9afbd0efadbe0f618392e9f9",
		"BASELINE_MODEL_TRANSCRIPT_SHA256":  "e30ee06ecfe69a6b47dc9899b194ec0dc69aa59af3461150d78dc07cea337041",
		"CANDIDATE_MODEL_TRANSCRIPT_SHA256": "c451d5cc4b4d3b18b839ab8b5847bd6c015ea8ffe9d8521539527338c0594fcc",
	} {
		if postTriage.Env[key] != want {
			t.Fatalf("post-triage evidence pin %s changed without reviewed evidence", key)
		}
	}
	modelEvidence := requireStep(t, postTriage, func(step benchmarkStep) bool {
		return step.Name == "Pin retained model observation and exchanges"
	})
	for _, want := range []string{
		`${MODEL_ATTESTATION_SHA256}  ${EVIDENCE_DIR}/model-runtime-attestation.json`,
		`${BASELINE_MODEL_TRANSCRIPT_SHA256}  ${EVIDENCE_DIR}/baseline-model-transcript.json`,
		`${CANDIDATE_MODEL_TRANSCRIPT_SHA256}  ${EVIDENCE_DIR}/candidate-model-transcript.json`,
	} {
		requireActiveLine(t, modelEvidence.Run, want)
	}
	candidateCheckout := requireStep(t, postTriage, func(step benchmarkStep) bool {
		return step.Name == "Checkout synapse candidate"
	})
	if candidateCheckout.With["ref"] != sourceSHA {
		t.Fatal("post-triage candidate checkout must bind the route source SHA")
	}
	postTriageAssertion := requireStep(t, postTriage, func(step benchmarkStep) bool {
		return step.Name == "Assert exact candidate revision"
	})
	requireActiveLine(t, postTriageAssertion.Run, `test "$(git rev-parse HEAD)" = "${{ needs.route.outputs.source_sha }}"`)
	securibench := requireJob(t, workflow, "securibench-scorecard")
	if securibench.Env["SEMGREP_IMAGE"] != "semgrep/semgrep@sha256:d1825c2c72110b5bfbf0602ff68f7f117322597a7c33037a79dba9f897f5f1f0" {
		t.Fatal("Securibench Semgrep lane must pin the verified container manifest")
	}
	if securibench.Env["SEMGREP_VERSION"] != "1.177.0" || securibench.Env["SEMGREP_RULES_REF"] != "a84ff9cc2453ca91d581380de4b8b3f272f6f4be" {
		t.Fatal("Securibench Semgrep lane must pin its tool and local rules revisions")
	}
	if _, atJobScope := securibench.Env["SEMGREP_REPORT_DIR"]; atJobScope {
		t.Fatal("runner.temp is unavailable in a job-level environment")
	}
	rulesCheckout := requireStep(t, securibench, func(step benchmarkStep) bool {
		return step.Name == "Checkout Semgrep Java rules (pinned)"
	})
	if rulesCheckout.Uses != "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" ||
		rulesCheckout.With["repository"] != "semgrep/semgrep-rules" ||
		rulesCheckout.With["ref"] != "${{ env.SEMGREP_RULES_REF }}" ||
		rulesCheckout.With["path"] != "semgrep-rules" {
		t.Fatal("Securibench Semgrep rules checkout must use the pinned local Java rules repository")
	}
	rulesVerification := requireStep(t, securibench, func(step benchmarkStep) bool {
		return step.Name == "Verify Semgrep rules revision"
	})
	requireActiveLine(t, rulesVerification.Run, `git -C semgrep-rules rev-parse HEAD)`)
	requireActiveLine(t, rulesVerification.Run, `test -d semgrep-rules/java`)
	semgrep := requireStep(t, securibench, func(step benchmarkStep) bool {
		return step.Name == "Run pinned Semgrep CE comparison"
	})
	if semgrep.Env["SEMGREP_REPORT_DIR"] != "${{ runner.temp }}/securibench-semgrep" {
		t.Fatal("Securibench Semgrep output must use a step-level runner temp path")
	}
	for _, want := range []string{
		`--network none`, `--read-only`, `--config /rules/java`, `/src/securibench/src`, `--sarif`,
		`test "$version" = "$SEMGREP_VERSION"`, `if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then`,
		`test -s "$SEMGREP_REPORT_DIR/semgrep.sarif"`, `jq -e --arg version "$SEMGREP_VERSION"`,
		`toolExecutionNotifications`,
		`semgrep/semgrep-rules`, `rules_commit`, `rules_scope`, `target_scope`, `source_sha`,
	} {
		requireActiveLine(t, semgrep.Run, want)
	}
	if strings.Contains(semgrep.Run, "p/java") {
		t.Fatal("Securibench Semgrep lane must not resolve mutable registry rules")
	}
	runScorecard := requireStep(t, securibench, func(step benchmarkStep) bool {
		return step.Name == "Run Securibench scorecard + per-CWE ratchet"
	})
	if runScorecard.Env["SYNAPSE_SEMGREP_SARIF"] != "${{ runner.temp }}/securibench-semgrep/semgrep.sarif" {
		t.Fatal("Securibench scorecard must parse the required Semgrep SARIF report")
	}
	upload := requireStep(t, securibench, func(step benchmarkStep) bool {
		return step.Uses == "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
	})
	if !strings.Contains(upload.With["path"], "${{ runner.temp }}/securibench-semgrep") {
		t.Fatal("Securibench artifact must retain the Semgrep SARIF and metadata")
	}
	adversarial := requireJob(t, workflow, "adversarial-regressions")
	regressions := requireStep(t, adversarial, func(step benchmarkStep) bool {
		return step.Name == "Run required adversarial cases"
	})
	for _, want := range []string{
		`CGO_ENABLED=1 go test -count=1 -json`,
		`./internal/domain/taint ./internal/infrastructure/tools/astwalk`,
		`TestPythonDisplayFieldSensitivityWidensOnDisplayUncertainty`,
		`TestPythonFrameworkEscapersSanitizeXSS`,
		`TestPythonShadowedSanitizerImportNotWalled`,
		`TestJavaLdapFilterPartialSanitizationFlags`,
		`TestJsTaintConfigurableSanitizersNotWalled`,
		`jq -e --arg name "$name"`,
	} {
		requireActiveLine(t, regressions.Run, want)
	}
	aggregate := requireJob(t, workflow, "aggregate")
	requireNeeds(t, aggregate, "route", "owasp-scorecard", "securibench-scorecard", "securibench-post-triage", "juliet-scorecard", "adversarial-regressions")
	if aggregate.If != "${{ always() }}" {
		t.Fatal("SAST aggregate must report every run")
	}
	step := requireOnlyRunStep(t, aggregate)
	for _, result := range []string{"ROUTE_RESULT", "OWASP_RESULT", "SECURIBENCH_RESULT", "JULIET_RESULT", "ADVERSARIAL_RESULT"} {
		requireActiveLine(t, step.Run, fmt.Sprintf(`test "$%s" = success`, result))
	}
	if !strings.Contains(step.Run, `test "$POST_TRIAGE_RESULT" = success`) || !strings.Contains(step.Run, `test "$POST_TRIAGE_RESULT" = skipped`) {
		t.Fatal("SAST aggregate must require post-triage replay for same-repository changes and skip it for forks")
	}
}

func requireJob(t *testing.T, workflow benchmarkWorkflow, name string) benchmarkJob {
	t.Helper()
	job, ok := workflow.Jobs[name]
	if !ok {
		t.Fatalf("workflow is missing %q job", name)
	}
	return job
}

func requireNeeds(t *testing.T, job benchmarkJob, required ...string) {
	t.Helper()
	if len(job.Needs) != len(required) {
		t.Fatalf("job needs %v, want %v", job.Needs, required)
	}
	for index, name := range required {
		if job.Needs[index] != name {
			t.Fatalf("job needs %v, want %v", job.Needs, required)
		}
	}
}

func requireStep(t *testing.T, job benchmarkJob, matches func(benchmarkStep) bool) benchmarkStep {
	t.Helper()
	for _, step := range job.Steps {
		if matches(step) {
			return step
		}
	}
	t.Fatal("workflow job is missing its required step")
	return benchmarkStep{}
}

func requireOnlyRunStep(t *testing.T, job benchmarkJob) benchmarkStep {
	t.Helper()
	for _, step := range job.Steps {
		if step.Run != "" {
			return step
		}
	}
	t.Fatal("workflow job is missing a shell assertion step")
	return benchmarkStep{}
}

func requireActiveLine(t *testing.T, script, want string) {
	t.Helper()
	for _, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") && strings.Contains(line, want) {
			return
		}
	}
	t.Fatalf("script is missing active line containing %q", want)
}

func readHostedBenchmarkWorkflow(t *testing.T, name string) benchmarkWorkflow {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate hosted benchmark workflow policy test source")
	}
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", ".github", "workflows", name)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read hosted benchmark workflow %q: %v", name, err)
	}
	var workflow benchmarkWorkflow
	if err := yaml.Unmarshal(content, &workflow); err != nil {
		t.Fatalf("parse hosted benchmark workflow %q: %v", name, err)
	}
	return workflow
}
