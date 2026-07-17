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

type OverviewGateOperator string

const (
	OverviewGateOperatorLE OverviewGateOperator = "<="
	OverviewGateOperatorGE OverviewGateOperator = ">="
	OverviewGateOperatorEQ OverviewGateOperator = "=="
	OverviewGateOperatorLT OverviewGateOperator = "<"
	OverviewGateOperatorGT OverviewGateOperator = ">"
)

type OverviewGateSource string

const (
	OverviewGateSourceDefault    OverviewGateSource = "default"
	OverviewGateSourceRepository OverviewGateSource = "repository"
	OverviewGateSourceManaged    OverviewGateSource = "managed"
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
	Operator  OverviewGateOperator
	Threshold float64
	Actual    float64
}

type OverviewGate struct {
	Status           OverviewGateStatus
	Key              *string
	Name             *string
	Source           *OverviewGateSource
	FailedConditions []OverviewGateCondition
}

type OverviewIssueSummary struct {
	NewCodeTotal         CountMetric
	AcceptedOverallTotal CountMetric
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
	IssueSummary   OverviewIssueSummary
	Overall        OverviewLens
	NewCode        OverviewLens
}

func (s *Service) Overview(ctx context.Context, tenantID shared.ID, key string) (Overview, error) {
	if strings.TrimSpace(key) == "" {
		return Overview{}, fmt.Errorf("%w: project key is required", shared.ErrValidation)
	}
	p, err := s.Get(ctx, tenantID, key)
	if err != nil {
		return Overview{}, err
	}
	projectView, err := validateOverviewProject(p)
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
		return notAnalyzedOverview(projectView), nil
	}
	return analyzedOverview(p, analysis)
}

func notAnalyzedOverview(p OverviewProject) Overview {
	reason := ReasonNoAnalysis
	return Overview{
		State:   OverviewStateNotAnalyzed,
		Project: p,
		IssueSummary: OverviewIssueSummary{
			NewCodeTotal:         unavailableCount(reason),
			AcceptedOverallTotal: unavailableCount(reason),
		},
		Overall: noAnalysisLens(),
		NewCode: noAnalysisLens(),
	}
}

func analyzedOverview(p *project.Project, analysis projectanalysis.Analysis) (Overview, error) {
	projectView, err := validateOverviewProject(p)
	if err != nil {
		return Overview{}, err
	}
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
	latest, err := overviewAnalysis(analysis)
	if err != nil {
		return Overview{}, err
	}
	if err := validateNewCodePeriod(latest.NewCode); err != nil {
		return Overview{}, err
	}
	return Overview{
		State:          OverviewStateAnalyzed,
		Project:        projectView,
		LatestAnalysis: &latest,
		Gate:           &gate,
		IssueSummary: OverviewIssueSummary{
			NewCodeTotal:         newIssues,
			AcceptedOverallTotal: unavailableCount(ReasonIssueLifecycleNotAvailable),
		},
		Overall: overall,
		NewCode: newCode,
	}, nil
}

func overviewProject(p *project.Project) OverviewProject {
	key, name := strings.TrimSpace(p.Key), strings.TrimSpace(p.Name)
	return OverviewProject{Key: key, Name: name}
}

func validateOverviewProject(p *project.Project) (OverviewProject, error) {
	if p == nil {
		return OverviewProject{}, fmt.Errorf("project snapshot is required")
	}
	out := overviewProject(p)
	if out.Key == "" {
		return OverviewProject{}, fmt.Errorf("project key is required")
	}
	if out.Name == "" {
		return OverviewProject{}, fmt.Errorf("project name is required")
	}
	return out, nil
}

func overviewAnalysis(analysis projectanalysis.Analysis) (OverviewAnalysis, error) {
	id := strings.TrimSpace(analysis.ID)
	if id == "" {
		return OverviewAnalysis{}, fmt.Errorf("analysis id is required")
	}
	if analysis.CreatedAt.IsZero() {
		return OverviewAnalysis{}, fmt.Errorf("analysis created_at is required")
	}
	period := OverviewNewCodePeriod{FirstAnalysis: true}
	if analysis.NewCode.PreviousID != "" {
		previous := strings.TrimSpace(analysis.NewCode.PreviousID)
		if previous == "" {
			return OverviewAnalysis{}, fmt.Errorf("baseline analysis id is required")
		}
		period = OverviewNewCodePeriod{HasBaseline: true, BaselineAnalysisID: &previous}
	}
	return OverviewAnalysis{
		ID: id, CreatedAt: analysis.CreatedAt, SourceRef: analysis.SourceRef,
		SourceCommit: analysis.SourceCommit, NewCode: period,
	}, nil
}

func validateNewCodePeriod(period OverviewNewCodePeriod) error {
	if period.FirstAnalysis && period.HasBaseline {
		return fmt.Errorf("invalid new-code period: first analysis cannot have a baseline")
	}
	if period.FirstAnalysis {
		if period.BaselineAnalysisID != nil {
			return fmt.Errorf("invalid new-code period: baseline id without baseline")
		}
		return nil
	}
	if !period.HasBaseline {
		return fmt.Errorf("invalid new-code period: baseline is required after first analysis")
	}
	if period.BaselineAnalysisID == nil || strings.TrimSpace(*period.BaselineAnalysisID) == "" {
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
	source, err := overviewGateSource(info.Source)
	if err != nil {
		return OverviewGate{}, err
	}
	out := OverviewGate{
		Status:           status,
		Key:              nonEmptyString(info.Key),
		Name:             nonEmptyString(info.Name),
		Source:           source,
		FailedConditions: []OverviewGateCondition{},
	}
	allPassed := true
	for _, result := range gate.Results {
		metric := strings.TrimSpace(result.Condition.Metric)
		if metric == "" {
			return OverviewGate{}, fmt.Errorf("gate condition metric is required")
		}
		if !qualitygate.ValidMetric(metric) {
			return OverviewGate{}, fmt.Errorf("unsupported gate condition metric")
		}
		operator, err := overviewGateOperator(result.Condition.Op)
		if err != nil {
			return OverviewGate{}, err
		}
		if !finiteNumber(result.Condition.Threshold) || !finiteNumber(result.Actual) {
			return OverviewGate{}, fmt.Errorf("invalid gate condition evidence")
		}
		if !result.Passed {
			allPassed = false
			out.FailedConditions = append(out.FailedConditions, OverviewGateCondition{
				Metric: metric, Operator: operator,
				Threshold: result.Condition.Threshold, Actual: result.Actual,
			})
		}
	}
	if gate.Passed != allPassed {
		return OverviewGate{}, fmt.Errorf("inconsistent gate result")
	}
	if gate.Passed && len(out.FailedConditions) != 0 {
		return OverviewGate{}, fmt.Errorf("passed gate has failed conditions")
	}
	if !gate.Passed && len(out.FailedConditions) == 0 {
		return OverviewGate{}, fmt.Errorf("failed gate has no failed conditions")
	}
	return out, nil
}

func nonEmptyString(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}

func overviewGateOperator(op qualitygate.Op) (OverviewGateOperator, error) {
	switch op {
	case qualitygate.OpLE:
		return OverviewGateOperatorLE, nil
	case qualitygate.OpGE:
		return OverviewGateOperatorGE, nil
	case qualitygate.OpEQ:
		return OverviewGateOperatorEQ, nil
	case qualitygate.OpLT:
		return OverviewGateOperatorLT, nil
	case qualitygate.OpGT:
		return OverviewGateOperatorGT, nil
	default:
		return "", fmt.Errorf("unsupported gate operator")
	}
}

func overviewGateSource(source string) (*OverviewGateSource, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return nil, nil
	}
	var out OverviewGateSource
	switch source {
	case string(OverviewGateSourceDefault):
		out = OverviewGateSourceDefault
	case string(OverviewGateSourceRepository):
		out = OverviewGateSourceRepository
	case string(OverviewGateSourceManaged):
		out = OverviewGateSourceManaged
	default:
		return nil, fmt.Errorf("unsupported gate source")
	}
	return &out, nil
}

func finiteNumber(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}
