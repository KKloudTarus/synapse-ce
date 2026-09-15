package qualitygate

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/rating"
)

func TestRenderMarkdownReturnsReusableSummary(t *testing.T) {
	result := Result{
		Passed: false,
		Results: []ConditionResult{
			{Condition: Condition{Metric: MetricNewCritical, Op: OpLE, Threshold: 0}, Actual: 1, Passed: false},
			{Condition: Condition{Metric: MetricCoveragePct, Op: OpGE, Threshold: 80}, Actual: 91.2, Passed: true},
		},
	}
	rep := rating.Report{Security: rating.GradeB, Reliability: rating.GradeA, Maintainability: rating.GradeC}

	got := RenderMarkdown("pull request #42 → main", rep, 3.25, "91.2%", result)
	for _, want := range []string{
		"## Synapse quality gate",
		"❌ **Quality gate failed** _(pull request #42 → main)_",
		"| Security | B |",
		"| Reliability | A |",
		"| Maintainability | C |",
		"Duplication 3.2% · Coverage 91.2%",
		"| `new_critical <= 0` | actual 1 | ❌ |",
		"| `coverage >= 80` | actual 91.2 | ✅ |",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("RenderMarkdown() missing %q:\n%s", want, got)
		}
	}
}

func TestRenderMarkdownPassed(t *testing.T) {
	got := RenderMarkdown("whole codebase", rating.Report{Security: rating.GradeA, Reliability: rating.GradeA, Maintainability: rating.GradeA}, 0, "n/a", Result{Passed: true})
	if !strings.Contains(got, "✅ **Quality gate passed**") {
		t.Fatalf("RenderMarkdown() = %q, want passed marker", got)
	}
}

func TestRenderMarkdownShowsNoDataForUnmeasuredCondition(t *testing.T) {
	result := Result{Passed: false, Results: []ConditionResult{{Condition: Condition{Metric: MetricCoveragePct, Op: OpGE, Threshold: 80}, Passed: false, Unmeasured: true}}}
	got := RenderMarkdown("whole codebase", rating.Report{}, 0, "n/a", result)
	if !strings.Contains(got, "| `coverage >= 80` | no data | ❌ |") {
		t.Fatalf("RenderMarkdown() = %q, want no-data condition", got)
	}
}
