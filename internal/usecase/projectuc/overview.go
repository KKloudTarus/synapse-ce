package projectuc

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rating"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

type OverviewState string

const (
	OverviewStateNotAnalyzed OverviewState = "not_analyzed"
	OverviewStateAnalyzed    OverviewState = "analyzed"
)

type MetricAvailability string

const (
	MetricAvailable     MetricAvailability = "available"
	MetricUnavailable   MetricAvailability = "unavailable"
	MetricNotSupplied   MetricAvailability = "not_supplied"
	MetricNotApplicable MetricAvailability = "not_applicable"
)

type UnavailableReason string

const (
	ReasonNoAnalysis                     UnavailableReason = "no_analysis"
	ReasonRatingNotAvailable             UnavailableReason = "rating_not_available"
	ReasonIssueLifecycleNotAvailable     UnavailableReason = "issue_lifecycle_not_available"
	ReasonSecurityHotspotsNotAvailable   UnavailableReason = "security_hotspots_not_available"
	ReasonChangedLineMetricsNotAvailable UnavailableReason = "changed_line_metrics_not_available"
	ReasonCoverageNotSupplied            UnavailableReason = "coverage_not_supplied"
	ReasonNoExecutableLines              UnavailableReason = "no_executable_lines"
	ReasonDuplicationNotAvailable        UnavailableReason = "duplication_not_available"
)

type OverviewGrade string

const (
	OverviewGradeA OverviewGrade = "A"
	OverviewGradeB OverviewGrade = "B"
	OverviewGradeC OverviewGrade = "C"
	OverviewGradeD OverviewGrade = "D"
	OverviewGradeE OverviewGrade = "E"
)

type OverviewGateStatus string

const (
	OverviewGatePassed OverviewGateStatus = "passed"
	OverviewGateFailed OverviewGateStatus = "failed"
)

type RatingMetric struct {
	Availability      MetricAvailability
	Grade             *OverviewGrade
	UnavailableReason *UnavailableReason
}

type PercentageMetric struct {
	Availability      MetricAvailability
	Value             *float64
	UnavailableReason *UnavailableReason
}

type CountMetric struct {
	Availability      MetricAvailability
	Value             *int
	UnavailableReason *UnavailableReason
}

type OverviewProject struct {
	Key  string
	Name string
}

type OverviewNewCodePeriod struct {
	FirstAnalysis      bool
	HasBaseline        bool
	BaselineAnalysisID *string
}

type OverviewAnalysis struct {
	ID           string
	CreatedAt    time.Time
	SourceRef    string
	SourceCommit string
	NewCode      OverviewNewCodePeriod
}

type OverviewGateCondition struct {
	Metric    string
	Operator  string
	Threshold float64
	Actual    float64
}

type OverviewGate struct {
	Status           OverviewGateStatus
	Key              *string
	Name             *string
	Source           *string
	FailedConditions []OverviewGateCondition
}

type OverviewIssueSummary struct {
	New      CountMetric
	Accepted CountMetric
}

type OverviewLens struct {
	Security                 RatingMetric
	Reliability              RatingMetric
	Maintainability          RatingMetric
	SecurityHotspotsReviewed PercentageMetric
	Coverage                 PercentageMetric
	Duplications             PercentageMetric
}

type Overview struct {
	State          OverviewState
	Project        OverviewProject
	LatestAnalysis *OverviewAnalysis
	Gate           *OverviewGate
	Issues         OverviewIssueSummary
	Overall        OverviewLens
	NewCode        OverviewLens
}

func (s *Service) Overview(ctx context.Context, tenantID shared.ID, key string) (Overview, error) {
	p, err := s.Get(ctx, tenantID, key)
	if err != nil {
		return Overview{}, err
	}
	if s.analyses == nil {
		return Overview{}, fmt.Errorf("project analysis store is not configured")
	}
	latest, err := s.analyses.LatestForProjects(ctx, tenantID, []shared.ID{p.ID})
	if err != nil {
		return Overview{}, fmt.Errorf("get latest project overview analysis: %w", err)
	}
	analysis, ok := latest[p.ID]
	if !ok {
		return notAnalyzedOverview(p), nil
	}
	return analyzedOverview(p, analysis)
}

func notAnalyzedOverview(p *project.Project) Overview {
	reason := ReasonNoAnalysis
	return Overview{
		State:   OverviewStateNotAnalyzed,
		Project: overviewProject(p),
		Issues: OverviewIssueSummary{
			New:      unavailableCount(reason),
			Accepted: unavailableCount(reason),
		},
		Overall: noAnalysisLens(),
		NewCode: noAnalysisLens(),
	}
}

func analyzedOverview(p *project.Project, analysis projectanalysis.Analysis) (Overview, error) {
	overall, err := overallLens(analysis)
	if err != nil {
		return Overview{}, err
	}
	newCode, err := newCodeLens(analysis)
	if err != nil {
		return Overview{}, err
	}
	gate, err := overviewGate(analysis.Gate, analysis.GateInfo)
	if err != nil {
		return Overview{}, err
	}
	newIssues, err := availableCount(analysis.NewCode.Counts.Total)
	if err != nil {
		return Overview{}, fmt.Errorf("invalid new issue count: %w", err)
	}
	latest := overviewAnalysis(analysis)
	if err := validateNewCodePeriod(latest.NewCode); err != nil {
		return Overview{}, err
	}
	return Overview{
		State:          OverviewStateAnalyzed,
		Project:        overviewProject(p),
		LatestAnalysis: &latest,
		Gate:           &gate,
		Issues: OverviewIssueSummary{
			New:      newIssues,
			Accepted: unavailableCount(ReasonIssueLifecycleNotAvailable),
		},
		Overall: overall,
		NewCode: newCode,
	}, nil
}

func overviewProject(p *project.Project) OverviewProject {
	return OverviewProject{Key: p.Key, Name: p.Name}
}

func overviewAnalysis(analysis projectanalysis.Analysis) OverviewAnalysis {
	period := OverviewNewCodePeriod{FirstAnalysis: true}
	if previous := strings.TrimSpace(analysis.NewCode.PreviousID); previous != "" {
		period = OverviewNewCodePeriod{HasBaseline: true, BaselineAnalysisID: &previous}
	}
	return OverviewAnalysis{
		ID: analysis.ID, CreatedAt: analysis.CreatedAt, SourceRef: analysis.SourceRef,
		SourceCommit: analysis.SourceCommit, NewCode: period,
	}
}

func validateNewCodePeriod(period OverviewNewCodePeriod) error {
	if period.FirstAnalysis && period.HasBaseline {
		return fmt.Errorf("invalid new-code period: first analysis cannot have a baseline")
	}
	if !period.HasBaseline && period.BaselineAnalysisID != nil {
		return fmt.Errorf("invalid new-code period: baseline id without baseline")
	}
	if period.HasBaseline && (period.BaselineAnalysisID == nil || strings.TrimSpace(*period.BaselineAnalysisID) == "") {
		return fmt.Errorf("invalid new-code period: baseline id is required")
	}
	return nil
}

func noAnalysisLens() OverviewLens {
	reason := ReasonNoAnalysis
	return OverviewLens{
		Security:                 unavailableRating(reason),
		Reliability:              unavailableRating(reason),
		Maintainability:          unavailableRating(reason),
		SecurityHotspotsReviewed: unavailablePercentage(reason),
		Coverage:                 unavailablePercentage(reason),
		Duplications:             unavailablePercentage(reason),
	}
}

func overallLens(analysis projectanalysis.Analysis) (OverviewLens, error) {
	security, err := ratingMetric(analysis.Rating.Security)
	if err != nil {
		return OverviewLens{}, fmt.Errorf("invalid overall security rating: %w", err)
	}
	reliability, err := ratingMetric(analysis.Rating.Reliability)
	if err != nil {
		return OverviewLens{}, fmt.Errorf("invalid overall reliability rating: %w", err)
	}
	maintainability, err := ratingMetric(analysis.Rating.Maintainability)
	if err != nil {
		return OverviewLens{}, fmt.Errorf("invalid overall maintainability rating: %w", err)
	}
	coverage, err := coverageMetric(analysis.Coverage)
	if err != nil {
		return OverviewLens{}, err
	}
	duplication, err := duplicationMetric(analysis.Duplication)
	if err != nil {
		return OverviewLens{}, err
	}
	return OverviewLens{
		Security: security, Reliability: reliability, Maintainability: maintainability,
		SecurityHotspotsReviewed: unavailablePercentage(ReasonSecurityHotspotsNotAvailable),
		Coverage:                 coverage, Duplications: duplication,
	}, nil
}

func newCodeLens(analysis projectanalysis.Analysis) (OverviewLens, error) {
	security, err := ratingMetric(analysis.NewCode.Rating.Security)
	if err != nil {
		return OverviewLens{}, fmt.Errorf("invalid new-code security rating: %w", err)
	}
	reliability, err := ratingMetric(analysis.NewCode.Rating.Reliability)
	if err != nil {
		return OverviewLens{}, fmt.Errorf("invalid new-code reliability rating: %w", err)
	}
	maintainability := unavailableRating(ReasonChangedLineMetricsNotAvailable)
	if analysis.NewCode.Rating.Maintainability != nil {
		maintainability, err = ratingMetric(*analysis.NewCode.Rating.Maintainability)
		if err != nil {
			return OverviewLens{}, fmt.Errorf("invalid new-code maintainability rating: %w", err)
		}
	}
	return OverviewLens{
		Security: security, Reliability: reliability, Maintainability: maintainability,
		SecurityHotspotsReviewed: unavailablePercentage(ReasonSecurityHotspotsNotAvailable),
		Coverage:                 unavailablePercentage(ReasonChangedLineMetricsNotAvailable),
		Duplications:             unavailablePercentage(ReasonChangedLineMetricsNotAvailable),
	}, nil
}

func ratingMetric(grade rating.Grade) (RatingMetric, error) {
	switch grade {
	case rating.GradeA:
		return availableRating(OverviewGradeA), nil
	case rating.GradeB:
		return availableRating(OverviewGradeB), nil
	case rating.GradeC:
		return availableRating(OverviewGradeC), nil
	case rating.GradeD:
		return availableRating(OverviewGradeD), nil
	case rating.GradeE:
		return availableRating(OverviewGradeE), nil
	case "", rating.Grade("?"):
		return unavailableRating(ReasonRatingNotAvailable), nil
	default:
		return RatingMetric{}, fmt.Errorf("unsupported grade %q", grade)
	}
}

func availableRating(grade OverviewGrade) RatingMetric {
	g := grade
	return RatingMetric{Availability: MetricAvailable, Grade: &g}
}

func unavailableRating(reason UnavailableReason) RatingMetric {
	r := reason
	return RatingMetric{Availability: MetricUnavailable, UnavailableReason: &r}
}

func availablePercentage(value float64) (PercentageMetric, error) {
	if !finitePercent(value) {
		return PercentageMetric{}, fmt.Errorf("invalid percentage %v", value)
	}
	v := value
	return PercentageMetric{Availability: MetricAvailable, Value: &v}, nil
}

func unavailablePercentage(reason UnavailableReason) PercentageMetric {
	r := reason
	return PercentageMetric{Availability: MetricUnavailable, UnavailableReason: &r}
}

func notSuppliedPercentage(reason UnavailableReason) PercentageMetric {
	r := reason
	return PercentageMetric{Availability: MetricNotSupplied, UnavailableReason: &r}
}

func notApplicablePercentage(reason UnavailableReason) PercentageMetric {
	r := reason
	return PercentageMetric{Availability: MetricNotApplicable, UnavailableReason: &r}
}

func availableCount(value int) (CountMetric, error) {
	if value < 0 {
		return CountMetric{}, fmt.Errorf("count must be non-negative")
	}
	v := value
	return CountMetric{Availability: MetricAvailable, Value: &v}, nil
}

func unavailableCount(reason UnavailableReason) CountMetric {
	r := reason
	return CountMetric{Availability: MetricUnavailable, UnavailableReason: &r}
}

func coverageMetric(report *measure.CoverageReport) (PercentageMetric, error) {
	if report == nil {
		return notSuppliedPercentage(ReasonCoverageNotSupplied), nil
	}
	if report.TotalLines < 0 || report.CoveredLines < 0 || report.CoveredLines > report.TotalLines {
		return PercentageMetric{}, fmt.Errorf("invalid coverage counts")
	}
	if report.TotalLines == 0 {
		return notApplicablePercentage(ReasonNoExecutableLines), nil
	}
	value := report.Percent()
	if !finitePercent(value) {
		return PercentageMetric{}, fmt.Errorf("invalid coverage percentage %v", value)
	}
	return availablePercentage(value)
}

func duplicationMetric(report measure.DuplicationReport) (PercentageMetric, error) {
	if report.TotalLines < 0 || report.DuplicatedLines < 0 || report.DuplicatedLines > report.TotalLines {
		return PercentageMetric{}, fmt.Errorf("invalid duplication counts")
	}
	if report.TotalLines == 0 {
		return notApplicablePercentage(ReasonDuplicationNotAvailable), nil
	}
	value := report.Density()
	if !finitePercent(value) {
		return PercentageMetric{}, fmt.Errorf("invalid duplication density %v", value)
	}
	return availablePercentage(value)
}

func finitePercent(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= 100
}

func overviewGate(gate qualitygate.Result, info projectanalysis.GateInfo) (OverviewGate, error) {
	status := OverviewGateFailed
	if gate.Passed {
		status = OverviewGatePassed
	}
	out := OverviewGate{
		Status:           status,
		Key:              nonEmptyString(info.Key),
		Name:             nonEmptyString(info.Name),
		Source:           nonEmptyString(info.Source),
		FailedConditions: []OverviewGateCondition{},
	}
	for _, result := range gate.Results {
		if math.IsNaN(result.Condition.Threshold) || math.IsInf(result.Condition.Threshold, 0) || math.IsNaN(result.Actual) || math.IsInf(result.Actual, 0) {
			return OverviewGate{}, fmt.Errorf("invalid gate condition evidence")
		}
		if result.Passed {
			continue
		}
		out.FailedConditions = append(out.FailedConditions, OverviewGateCondition{
			Metric: result.Condition.Metric, Operator: string(result.Condition.Op),
			Threshold: result.Condition.Threshold, Actual: result.Actual,
		})
	}
	return out, nil
}

func nonEmptyString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
