package projectuc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rating"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
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

const (
	decTenant  = shared.ID("tenant-a")
	decProject = shared.ID("proj-1")
)

// decorationService builds a Service whose project repo holds one project keyed by (decTenant,
// decProject), opted into decoration per the argument, plus the recording decorator.
func decorationService(t *testing.T, optedIn bool) (*Service, *recordingPRDecorator) {
	t.Helper()
	repo := memory.NewProjectRepository()
	src := project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}
	p, err := project.New(decProject, decTenant, "App", "app", src, nil, "", time.Unix(0, 0))
	if err != nil {
		t.Fatalf("new project: %v", err)
	}
	if err := repo.Create(context.Background(), p); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if optedIn {
		if err := repo.SetPullRequestDecoration(context.Background(), decTenant, "app", true); err != nil {
			t.Fatalf("enable decoration: %v", err)
		}
	}
	fake := &recordingPRDecorator{}
	svc := &Service{repo: repo}
	svc.SetPRDecorator(fake)
	return svc, fake
}

func prAnalysis() projectanalysis.Analysis {
	newCoverage := 72.5
	return projectanalysis.Analysis{
		TenantID:  decTenant.String(),
		ProjectID: decProject.String(),
		CI: &projectanalysis.CIContext{
			Provider: "github-actions", RepoSlug: "acme/widget", HeadSHA: "abc123", PullRequest: "42", TargetBranch: "main",
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
		NewCode:  projectanalysis.NewCode{Counts: projectanalysis.Counts{Total: 3}},
		Snapshot: measure.Snapshot{NewCodeCoverage: measure.DecimalMetric{Availability: measure.AvailabilityAvailable, Value: &newCoverage}},
	}
}

func TestDecorateProjectAnalysisPublishesCompletePayloadWhenOptedIn(t *testing.T) {
	svc, fake := decorationService(t, true)
	svc.decorateProjectAnalysis(context.Background(), prAnalysis())
	if fake.calls != 1 {
		t.Fatalf("decorator calls = %d, want 1", fake.calls)
	}
	if fake.got.Provider != "github-actions" {
		t.Fatalf("provider = %q, want the CI provider claim for multiplex dispatch", fake.got.Provider)
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

func TestDecorateProjectAnalysisSkipsWhenProjectNotOptedIn(t *testing.T) {
	svc, fake := decorationService(t, false)
	svc.decorateProjectAnalysis(context.Background(), prAnalysis())
	if fake.calls != 0 {
		t.Fatalf("decoration must be skipped for a project that has not opted in; calls = %d", fake.calls)
	}
}

func TestDecorateProjectAnalysisIsFailSoftAndSkipsPartialIdentity(t *testing.T) {
	svc, fake := decorationService(t, true)
	fake.err = errors.New("forge unavailable")
	svc.decorateProjectAnalysis(context.Background(), prAnalysis()) // adapter error must not escape
	if fake.calls != 1 {
		t.Fatalf("decorator calls = %d, want 1", fake.calls)
	}

	partial := prAnalysis()
	partial.CI.TargetBranch = ""
	svc.decorateProjectAnalysis(context.Background(), partial)
	if fake.calls != 1 {
		t.Fatalf("partial target should be skipped; calls = %d", fake.calls)
	}
}
