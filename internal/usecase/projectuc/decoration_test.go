package projectuc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rating"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type recordingPRDecorator struct {
	calls int
	got   ports.PRDecoration
	err   error
}

func (f *recordingPRDecorator) Decorate(_ context.Context, d ports.PRDecoration) error {
	f.calls++
	f.got = d
	return f.err
}

func TestDecorateProjectAnalysisPublishesCompletePayload(t *testing.T) {
	fake := &recordingPRDecorator{}
	svc := &Service{}
	svc.SetPRDecorator(fake)
	newCoverage := 72.5
	analysis := projectanalysis.Analysis{
		CI: &projectanalysis.CIContext{
			RepoSlug: "acme/widget", HeadSHA: "abc123", PullRequest: "42", TargetBranch: "main",
		},
		Rating: rating.Report{Security: rating.GradeA, Reliability: rating.GradeB, Maintainability: rating.GradeA},
		Gate: qualitygate.Result{Passed: false, Results: []qualitygate.ConditionResult{{
			Condition: qualitygate.Condition{Metric: qualitygate.MetricNewCritical, Op: qualitygate.OpLE, Threshold: 0}, Actual: 1, Passed: false,
		}}},
		Annotations: []projectanalysis.Annotation{{FindingKey: "f-1", RuleKey: "rule-1"}},
		FileChanges: []projectanalysis.FileChange{{
			Status: projectanalysis.FileStatusAdded, NewPath: "src/a.go",
			Hunks: []projectanalysis.DiffHunk{{NewStart: 1, NewLines: 1, Rows: []projectanalysis.DiffRow{{Kind: projectanalysis.DiffRowAdded, NewLine: 1}}}},
		}},
		NewCode: projectanalysis.NewCode{Counts: projectanalysis.Counts{Total: 3}},
		Snapshot: measure.Snapshot{NewCodeCoverage: measure.DecimalMetric{
			Availability: measure.AvailabilityAvailable, Value: &newCoverage,
		}},
	}

	svc.decorateProjectAnalysis(context.Background(), analysis)
	if fake.calls != 1 {
		t.Fatalf("decorator calls = %d, want 1", fake.calls)
	}
	if fake.got.Target.Repository != "acme/widget" || fake.got.Target.CommitSHA != "abc123" || fake.got.Target.PullRequest != "42" || fake.got.Target.TargetBranch != "main" {
		t.Fatalf("target = %+v", fake.got.Target)
	}
	if len(fake.got.Annotations) != 1 || fake.got.Annotations[0].FindingKey != "f-1" {
		t.Fatalf("annotations = %+v", fake.got.Annotations)
	}
	if len(fake.got.FileChanges) != 1 || fake.got.FileChanges[0].NewPath != "src/a.go" {
		t.Fatalf("file changes = %+v", fake.got.FileChanges)
	}
	if fake.got.NewIssues == nil || *fake.got.NewIssues != 3 || fake.got.NewCoverage == nil || *fake.got.NewCoverage != 72.5 {
		t.Fatalf("new-code decoration = issues:%v coverage:%v", fake.got.NewIssues, fake.got.NewCoverage)
	}
	if !strings.Contains(fake.got.Summary, "pull request #42 → main") || !strings.Contains(fake.got.Summary, "Quality gate failed") {
		t.Fatalf("summary = %q", fake.got.Summary)
	}
}

func TestDecorateProjectAnalysisIsFailSoftAndSkipsPartialIdentity(t *testing.T) {
	fake := &recordingPRDecorator{err: errors.New("forge unavailable")}
	svc := &Service{}
	svc.SetPRDecorator(fake)
	complete := projectanalysis.Analysis{CI: &projectanalysis.CIContext{RepoSlug: "acme/widget", HeadSHA: "abc", PullRequest: "1", TargetBranch: "main"}, Gate: qualitygate.Result{Passed: true}}
	svc.decorateProjectAnalysis(context.Background(), complete) // adapter error must not escape
	if fake.calls != 1 {
		t.Fatalf("decorator calls = %d, want 1", fake.calls)
	}

	partial := projectanalysis.Analysis{CI: &projectanalysis.CIContext{RepoSlug: "acme/widget", PullRequest: "2"}}
	svc.decorateProjectAnalysis(context.Background(), partial)
	if fake.calls != 1 {
		t.Fatalf("partial target should be skipped; calls = %d", fake.calls)
	}
}
