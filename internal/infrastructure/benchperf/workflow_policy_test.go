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
	securibench := requireJob(t, workflow, "securibench-scorecard")
	if securibench.Env["SEMGREP_IMAGE"] != "semgrep/semgrep@sha256:d1825c2c72110b5bfbf0602ff68f7f117322597a7c33037a79dba9f897f5f1f0" {
		t.Fatal("Securibench Semgrep lane must pin the verified container manifest")
	}
	if securibench.Env["SEMGREP_VERSION"] != "1.177.0" || securibench.Env["SEMGREP_RULES_REF"] != "a84ff9cc2453ca91d581380de4b8b3f272f6f4be" {
		t.Fatal("Securibench Semgrep lane must pin its tool and local rules revisions")
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
	if runScorecard.Env["SYNAPSE_SEMGREP_SARIF"] != "${{ env.SEMGREP_REPORT_DIR }}/semgrep.sarif" {
		t.Fatal("Securibench scorecard must parse the required Semgrep SARIF report")
	}
	upload := requireStep(t, securibench, func(step benchmarkStep) bool {
		return step.Uses == "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
	})
	if !strings.Contains(upload.With["path"], "${{ env.SEMGREP_REPORT_DIR }}") {
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
	requireNeeds(t, aggregate, "route", "owasp-scorecard", "securibench-scorecard", "juliet-scorecard", "adversarial-regressions")
	if aggregate.If != "${{ always() }}" {
		t.Fatal("SAST aggregate must report every run")
	}
	step := requireOnlyRunStep(t, aggregate)
	for _, result := range []string{"ROUTE_RESULT", "OWASP_RESULT", "SECURIBENCH_RESULT", "JULIET_RESULT", "ADVERSARIAL_RESULT"} {
		requireActiveLine(t, step.Run, fmt.Sprintf(`test "$%s" = success`, result))
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
