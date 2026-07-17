package projectuc

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rating"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type overviewProjectRepoSpy struct {
	project *project.Project
	err     error
	calls   int
	tenant  shared.ID
	key     string
}

func (r *overviewProjectRepoSpy) Create(context.Context, *project.Project) error {
	panic("unexpected Create")
}
func (r *overviewProjectRepoSpy) List(context.Context, shared.ID) ([]*project.Project, error) {
	panic("unexpected List")
}
func (r *overviewProjectRepoSpy) GetByKey(_ context.Context, tenantID shared.ID, key string) (*project.Project, error) {
	r.calls++
	r.tenant, r.key = tenantID, key
	if r.err != nil {
		return nil, r.err
	}
	return r.project, nil
}
func (r *overviewProjectRepoSpy) GetByID(context.Context, shared.ID, shared.ID) (*project.Project, error) {
	panic("unexpected GetByID")
}
func (r *overviewProjectRepoSpy) UpdateGate(context.Context, shared.ID, string, string) error {
	panic("unexpected UpdateGate")
}
func (r *overviewProjectRepoSpy) CountByGate(context.Context, shared.ID, string) (int, error) {
	panic("unexpected CountByGate")
}
func (r *overviewProjectRepoSpy) DeleteByKey(context.Context, shared.ID, string) error {
	panic("unexpected DeleteByKey")
}

type overviewAnalysisStoreSpy struct {
	latest     map[shared.ID]projectanalysis.Analysis
	err        error
	calls      int
	tenant     shared.ID
	projectIDs []shared.ID
}

func (s *overviewAnalysisStoreSpy) Save(context.Context, projectanalysis.Analysis) error {
	panic("unexpected Save")
}
func (s *overviewAnalysisStoreSpy) SaveWithResult(context.Context, projectanalysis.Analysis, []byte) error {
	panic("unexpected SaveWithResult")
}
func (s *overviewAnalysisStoreSpy) LatestWithResult(context.Context, shared.ID, shared.ID) (projectanalysis.Analysis, []byte, error) {
	panic("unexpected LatestWithResult")
}
func (s *overviewAnalysisStoreSpy) LatestForProjects(_ context.Context, tenantID shared.ID, projectIDs []shared.ID) (map[shared.ID]projectanalysis.Analysis, error) {
	s.calls++
	s.tenant = tenantID
	s.projectIDs = append([]shared.ID(nil), projectIDs...)
	if s.err != nil {
		return nil, s.err
	}
	return s.latest, nil
}
func (s *overviewAnalysisStoreSpy) List(context.Context, shared.ID, shared.ID, int, time.Time, shared.ID) ([]projectanalysis.Analysis, bool, error) {
	panic("unexpected List")
}
func (s *overviewAnalysisStoreSpy) Get(context.Context, shared.ID, shared.ID, shared.ID) (projectanalysis.Analysis, error) {
	panic("unexpected Get")
}

func overviewTestProject() *project.Project {
	return &project.Project{ID: "p1", TenantID: "tenant-a", Key: "payments-api", Name: "Payments API"}
}

func TestOverviewProjectNotFound(t *testing.T) {
	repo := &overviewProjectRepoSpy{err: shared.ErrNotFound}
	svc := NewService(repo, nil, fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(&overviewAnalysisStoreSpy{})
	_, err := svc.Overview(context.Background(), "tenant-a", "missing")
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("error=%v, want not found", err)
	}
}

func TestOverviewRequiresAnalysisStore(t *testing.T) {
	svc := NewService(&overviewProjectRepoSpy{project: overviewTestProject()}, nil, fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	_, err := svc.Overview(context.Background(), "tenant-a", "payments-api")
	if err == nil || errors.Is(err, shared.ErrNotFound) || errors.Is(err, shared.ErrValidation) {
		t.Fatalf("error=%v, want internal configuration error", err)
	}
}

func TestOverviewNotAnalyzedUsesExplicitUnavailableMetrics(t *testing.T) {
	repo := &overviewProjectRepoSpy{project: overviewTestProject()}
	store := &overviewAnalysisStoreSpy{latest: map[shared.ID]projectanalysis.Analysis{}}
	svc := NewService(repo, nil, fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(store)

	got, err := svc.Overview(context.Background(), "tenant-a", "  payments-api ")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != OverviewStateNotAnalyzed || got.Project.Key != "payments-api" || got.LatestAnalysis != nil || got.Gate != nil {
		t.Fatalf("overview=%+v", got)
	}
	if repo.calls != 1 || repo.tenant != "tenant-a" || repo.key != "payments-api" {
		t.Fatalf("project lookup calls=%d tenant=%q key=%q", repo.calls, repo.tenant, repo.key)
	}
	if store.calls != 1 || store.tenant != "tenant-a" || len(store.projectIDs) != 1 || store.projectIDs[0] != "p1" {
		t.Fatalf("latest calls=%d tenant=%q ids=%v", store.calls, store.tenant, store.projectIDs)
	}
	assertRatingUnavailable(t, got.Overall.Security, ReasonNoAnalysis)
	assertRatingUnavailable(t, got.NewCode.Maintainability, ReasonNoAnalysis)
	assertPercentageUnavailable(t, got.Overall.Coverage, MetricUnavailable, ReasonNoAnalysis)
	assertPercentageUnavailable(t, got.NewCode.Duplications, MetricUnavailable, ReasonNoAnalysis)
	assertCountUnavailable(t, got.Issues.New, ReasonNoAnalysis)
	assertCountUnavailable(t, got.Issues.Accepted, ReasonNoAnalysis)
}

func TestOverviewAnalyzedMapsImmutableSnapshot(t *testing.T) {
	maintainability := rating.GradeB
	created := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	analysis := projectanalysis.Analysis{
		ID: "analysis-42", TenantID: "tenant-a", ProjectID: "p1", ProjectKey: "payments-api",
		CreatedAt: created, SourceRef: "main", SourceCommit: "abc123",
		Rating: rating.Report{Security: rating.GradeB, Reliability: rating.GradeA, Maintainability: rating.GradeC},
		NewCode: projectanalysis.NewCode{
			PreviousID: "analysis-41",
			Counts:     projectanalysis.Counts{Total: 4},
			Rating:     projectanalysis.NewCodeRating{Security: rating.GradeA, Reliability: rating.GradeB, Maintainability: &maintainability},
		},
		Coverage:    &measure.CoverageReport{CoveredLines: 72349, TotalLines: 100000},
		Duplication: measure.DuplicationReport{DuplicatedLines: 17, TotalLines: 400},
		Gate: qualitygate.Result{Passed: false, Results: []qualitygate.ConditionResult{
			{Condition: qualitygate.Condition{Metric: "new_critical", Op: qualitygate.OpLE, Threshold: 0}, Actual: 0, Passed: true},
			{Condition: qualitygate.Condition{Metric: "new_high", Op: qualitygate.OpLE, Threshold: 0}, Actual: 2, Passed: false},
		}},
		GateInfo:       projectanalysis.GateInfo{Key: "release", Name: "Release", Source: "managed"},
		InternalIssues: []projectanalysis.Issue{{Key: "secret-sentinel"}},
	}
	svc := NewService(&overviewProjectRepoSpy{project: overviewTestProject()}, nil, fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(&overviewAnalysisStoreSpy{latest: map[shared.ID]projectanalysis.Analysis{"p1": analysis}})

	got, err := svc.Overview(context.Background(), "tenant-a", "payments-api")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != OverviewStateAnalyzed || got.LatestAnalysis == nil || got.LatestAnalysis.ID != "analysis-42" || got.LatestAnalysis.CreatedAt != created {
		t.Fatalf("overview=%+v", got)
	}
	if !got.LatestAnalysis.NewCode.HasBaseline || got.LatestAnalysis.NewCode.FirstAnalysis || got.LatestAnalysis.NewCode.BaselineAnalysisID == nil || *got.LatestAnalysis.NewCode.BaselineAnalysisID != "analysis-41" {
		t.Fatalf("new-code period=%+v", got.LatestAnalysis.NewCode)
	}
	assertRatingAvailable(t, got.Overall.Security, OverviewGradeB)
	assertRatingAvailable(t, got.Overall.Reliability, OverviewGradeA)
	assertRatingAvailable(t, got.Overall.Maintainability, OverviewGradeC)
	assertRatingAvailable(t, got.NewCode.Maintainability, OverviewGradeB)
	assertPercentageAvailable(t, got.Overall.Coverage, 72.349)
	assertPercentageAvailable(t, got.Overall.Duplications, 4.25)
	assertPercentageUnavailable(t, got.NewCode.Coverage, MetricUnavailable, ReasonChangedLineMetricsNotAvailable)
	assertPercentageUnavailable(t, got.Overall.SecurityHotspotsReviewed, MetricUnavailable, ReasonSecurityHotspotsNotAvailable)
	assertCountAvailable(t, got.Issues.New, 4)
	assertCountUnavailable(t, got.Issues.Accepted, ReasonIssueLifecycleNotAvailable)
	if got.Gate == nil || got.Gate.Status != OverviewGateFailed || len(got.Gate.FailedConditions) != 1 || got.Gate.FailedConditions[0].Metric != "new_high" {
		t.Fatalf("gate=%+v", got.Gate)
	}
	if got.Gate.Key == nil || *got.Gate.Key != "release" || got.Gate.Name == nil || *got.Gate.Name != "Release" || got.Gate.Source == nil || *got.Gate.Source != "managed" {
		t.Fatalf("gate metadata=%+v", got.Gate)
	}
}

func TestOverviewMapsUnavailableAndNotApplicableMetrics(t *testing.T) {
	got, err := analyzedOverview(overviewTestProject(), projectanalysis.Analysis{
		ID: "analysis-1", ProjectID: "p1", CreatedAt: time.Unix(1, 0),
		Rating:      rating.Report{Security: rating.Grade("?"), Reliability: "", Maintainability: rating.GradeA},
		NewCode:     projectanalysis.NewCode{Rating: projectanalysis.NewCodeRating{Security: rating.Grade("?"), Reliability: rating.GradeA}},
		Coverage:    &measure.CoverageReport{},
		Duplication: measure.DuplicationReport{},
		Gate:        qualitygate.Result{Passed: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertRatingUnavailable(t, got.Overall.Security, ReasonRatingNotAvailable)
	assertRatingUnavailable(t, got.Overall.Reliability, ReasonRatingNotAvailable)
	assertRatingUnavailable(t, got.NewCode.Security, ReasonRatingNotAvailable)
	assertRatingUnavailable(t, got.NewCode.Maintainability, ReasonChangedLineMetricsNotAvailable)
	assertPercentageUnavailable(t, got.Overall.Coverage, MetricNotApplicable, ReasonNoExecutableLines)
	assertPercentageUnavailable(t, got.Overall.Duplications, MetricNotApplicable, ReasonDuplicationNotAvailable)
	if got.Gate == nil || got.Gate.Status != OverviewGatePassed || len(got.Gate.FailedConditions) != 0 {
		t.Fatalf("gate=%+v", got.Gate)
	}
	if got.LatestAnalysis == nil || !got.LatestAnalysis.NewCode.FirstAnalysis || got.LatestAnalysis.NewCode.HasBaseline || got.LatestAnalysis.NewCode.BaselineAnalysisID != nil {
		t.Fatalf("period=%+v", got.LatestAnalysis)
	}
}

func TestOverviewCoverageNotSupplied(t *testing.T) {
	got, err := analyzedOverview(overviewTestProject(), projectanalysis.Analysis{
		ID: "analysis-1", ProjectID: "p1", CreatedAt: time.Unix(1, 0),
		Rating:      rating.Report{Security: rating.GradeA, Reliability: rating.GradeA, Maintainability: rating.GradeA},
		NewCode:     projectanalysis.NewCode{Rating: projectanalysis.NewCodeRating{Security: rating.GradeA, Reliability: rating.GradeA}},
		Duplication: measure.DuplicationReport{DuplicatedLines: 0, TotalLines: 10},
		Gate:        qualitygate.Result{Passed: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertPercentageUnavailable(t, got.Overall.Coverage, MetricNotSupplied, ReasonCoverageNotSupplied)
}

func TestOverviewRejectsInvalidPersistedEvidence(t *testing.T) {
	valid := projectanalysis.Analysis{
		ID: "analysis-1", ProjectID: "p1", CreatedAt: time.Unix(1, 0),
		Rating:      rating.Report{Security: rating.GradeA, Reliability: rating.GradeA, Maintainability: rating.GradeA},
		NewCode:     projectanalysis.NewCode{Counts: projectanalysis.Counts{Total: 1}, Rating: projectanalysis.NewCodeRating{Security: rating.GradeA, Reliability: rating.GradeA}},
		Coverage:    &measure.CoverageReport{CoveredLines: 1, TotalLines: 1},
		Duplication: measure.DuplicationReport{DuplicatedLines: 0, TotalLines: 1},
		Gate:        qualitygate.Result{Passed: true},
	}
	tests := map[string]func(projectanalysis.Analysis) projectanalysis.Analysis{
		"bad grade": func(a projectanalysis.Analysis) projectanalysis.Analysis {
			a.Rating.Security = rating.Grade("Z")
			return a
		},
		"bad coverage": func(a projectanalysis.Analysis) projectanalysis.Analysis {
			a.Coverage = &measure.CoverageReport{CoveredLines: 2, TotalLines: 1}
			return a
		},
		"bad duplication": func(a projectanalysis.Analysis) projectanalysis.Analysis {
			a.Duplication = measure.DuplicationReport{DuplicatedLines: 2, TotalLines: 1}
			return a
		},
		"bad gate numeric": func(a projectanalysis.Analysis) projectanalysis.Analysis {
			a.Gate = qualitygate.Result{Passed: false, Results: []qualitygate.ConditionResult{{Condition: qualitygate.Condition{Metric: "coverage", Op: qualitygate.OpGE, Threshold: math.NaN()}, Actual: 1}}}
			return a
		},
		"bad count": func(a projectanalysis.Analysis) projectanalysis.Analysis {
			a.NewCode.Counts.Total = -1
			return a
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := analyzedOverview(overviewTestProject(), mutate(valid)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func assertRatingAvailable(t *testing.T, got RatingMetric, grade OverviewGrade) {
	t.Helper()
	if got.Availability != MetricAvailable || got.Grade == nil || *got.Grade != grade || got.UnavailableReason != nil {
		t.Fatalf("rating=%+v, want available %s", got, grade)
	}
}

func assertRatingUnavailable(t *testing.T, got RatingMetric, reason UnavailableReason) {
	t.Helper()
	if got.Availability == MetricAvailable || got.Grade != nil || got.UnavailableReason == nil || *got.UnavailableReason != reason {
		t.Fatalf("rating=%+v, want unavailable %s", got, reason)
	}
}

func assertPercentageAvailable(t *testing.T, got PercentageMetric, value float64) {
	t.Helper()
	if got.Availability != MetricAvailable || got.Value == nil || *got.Value != value || got.UnavailableReason != nil {
		t.Fatalf("percentage=%+v, want %v", got, value)
	}
}

func assertPercentageUnavailable(t *testing.T, got PercentageMetric, availability MetricAvailability, reason UnavailableReason) {
	t.Helper()
	if got.Availability != availability || got.Value != nil || got.UnavailableReason == nil || *got.UnavailableReason != reason {
		t.Fatalf("percentage=%+v, want %s %s", got, availability, reason)
	}
}

func assertCountAvailable(t *testing.T, got CountMetric, value int) {
	t.Helper()
	if got.Availability != MetricAvailable || got.Value == nil || *got.Value != value || got.UnavailableReason != nil {
		t.Fatalf("count=%+v, want %d", got, value)
	}
}

func assertCountUnavailable(t *testing.T, got CountMetric, reason UnavailableReason) {
	t.Helper()
	if got.Availability == MetricAvailable || got.Value != nil || got.UnavailableReason == nil || *got.UnavailableReason != reason {
		t.Fatalf("count=%+v, want unavailable %s", got, reason)
	}
}
