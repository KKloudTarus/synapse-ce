// Package projectanalysis models immutable, tenant-scoped Project analysis snapshots.
package projectanalysis

import (
	"fmt"
	"sort"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/hotspot"
	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/rating"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Issue is the compact, stable identity retained to derive the next New Code period.
type Issue struct {
	Key      string          `json:"key"`
	Kind     finding.Kind    `json:"kind"`
	Severity shared.Severity `json:"severity"`
	Status   finding.Status  `json:"status"`
}

// Counts groups issues along the dimensions exposed by Activity.
type Counts struct {
	Total      int            `json:"total"`
	ByKind     map[string]int `json:"by_kind"`
	BySeverity map[string]int `json:"by_severity"`
	ByStatus   map[string]int `json:"by_status"`
}

// Delta is a signed comparison with the immediately previous successful analysis.
type Delta struct {
	Issues   Counts             `json:"issues"`
	Measures map[string]float64 `json:"measures"`
	Ratings  map[string]int     `json:"ratings"`
}

// NewCode retains the derived period state used by the default gate.
type NewCode struct {
	PreviousID string        `json:"previous_id,omitempty"`
	Counts     Counts        `json:"counts"`
	Rating     NewCodeRating `json:"rating"`
}

// NewCodeRating omits maintainability until Project scans retain changed-line LOC.
type NewCodeRating struct {
	Security        rating.Grade  `json:"security"`
	Reliability     rating.Grade  `json:"reliability"`
	Maintainability *rating.Grade `json:"maintainability"`
}

// GateInfo records which policy produced the immutable evaluated result.
type GateInfo struct {
	Key    string `json:"key,omitempty"`
	Name   string `json:"name"`
	Source string `json:"source"`
}

// Analysis is an append-only Project analysis snapshot. InternalIssues never crosses
// the HTTP boundary; it is only persisted to compute the next snapshot's identity set.
type Analysis struct {
	ID             string                    `json:"id"`
	TenantID       string                    `json:"tenant_id"`
	ProjectID      string                    `json:"project_id"`
	ProjectKey     string                    `json:"project_key"`
	CreatedAt      time.Time                 `json:"created_at"`
	SourceRef      string                    `json:"source_ref,omitempty"`
	SourceCommit   string                    `json:"source_commit,omitempty"`
	Measures       qualitygate.Snapshot      `json:"measures"`
	Gate           qualitygate.Result        `json:"gate"`
	GateInfo       GateInfo                  `json:"gate_info"`
	Issues         Counts                    `json:"issues"`
	InternalIssues []Issue                   `json:"internal_issues"`
	NewCode        NewCode                   `json:"new_code"`
	Delta          *Delta                    `json:"delta"`
	Coverage       *measure.CoverageReport   `json:"coverage"`
	Duplication    measure.DuplicationReport `json:"duplication"`
	Rating         rating.Report             `json:"rating"`
	Hotspots       hotspot.Summary           `json:"hotspots"`
	NewHotspots    hotspot.Summary           `json:"new_hotspots"`
}

// Input supplies one completed scan's project-facing facts. Findings must be the
// merged root and code-quality findings, not two independently counted lists.
type Input struct {
	ID           string
	TenantID     shared.ID
	ProjectID    shared.ID
	ProjectKey   string
	CreatedAt    time.Time
	SourceRef    string
	SourceCommit string
	Findings     []finding.Finding
	Gate         qualitygate.Gate
	GateSource   string
	GateExempt   map[string]bool
	LinesOfCode  int
	Coverage     *measure.CoverageReport
	Duplication  measure.DuplicationReport
	Previous     *Analysis
	Hotspots     hotspot.Summary
	NewHotspots  hotspot.Summary
}

// Build returns one immutable snapshot and evaluates the built-in gate at creation.
func Build(in Input) (Analysis, error) {
	pairs, err := compactIssues(finding.Publishable(in.Findings))
	if err != nil {
		return Analysis{}, err
	}
	issues := make([]Issue, len(pairs))
	normalized := make([]finding.Finding, len(pairs))
	currentByKey := make(map[string]finding.Finding, len(pairs))
	for i, pair := range pairs {
		issues[i], normalized[i], currentByKey[pair.issue.Key] = pair.issue, pair.finding, pair.finding
	}
	counts := countIssues(issues)

	previous := map[string]Issue{}
	previousID := ""
	if in.Previous != nil {
		previousID = in.Previous.ID
		for _, issue := range in.Previous.InternalIssues {
			previous[issue.Key] = issue
		}
	}
	newIssues := make([]Issue, 0, len(issues))
	newFindings := make([]finding.Finding, 0, len(issues))
	gateFindings := make([]finding.Finding, 0, len(normalized))
	gateNewFindings := make([]finding.Finding, 0, len(normalized))
	for _, issue := range issues {
		current := currentByKey[issue.Key]
		isNew := materiallyNew(issue, previous[issue.Key], previous[issue.Key].Key == "")
		if isNew {
			newIssues = append(newIssues, issue)
			newFindings = append(newFindings, current)
		}
		if in.GateExempt[issue.Key] {
			continue
		}
		gateFindings = append(gateFindings, current)
		if isNew {
			gateNewFindings = append(gateNewFindings, current)
		}
	}
	newCounts := countIssues(newIssues)
	gateIssues := compactIssuesOnly(gateFindings)
	gateNewIssues := compactIssuesOnly(gateNewFindings)
	overallRating := rating.Compute(normalized, in.LinesOfCode)
	newRating := rating.Compute(newFindings, 0)
	gateOverallRating := rating.Compute(gateFindings, in.LinesOfCode)
	measures := buildMeasures(countIssues(gateIssues), countIssues(gateNewIssues), gateOverallRating, in.Duplication, in.Coverage, in.Hotspots, in.NewHotspots)
	gateDef := in.Gate
	gateSource := in.GateSource
	if len(gateDef.Conditions) == 0 {
		gateDef = qualitygate.Default()
		gateSource = "default"
	}
	gateName := gateDef.Name
	if gateName == "" {
		if gateSource == "repository" {
			gateName = "Repository gate"
		} else {
			gateName = "Quality gate"
		}
	}
	gate := qualitygate.Evaluate(gateDef, measures)

	return Analysis{
		ID: in.ID, TenantID: in.TenantID.String(), ProjectID: in.ProjectID.String(),
		ProjectKey: in.ProjectKey, CreatedAt: in.CreatedAt, SourceRef: in.SourceRef,
		SourceCommit: in.SourceCommit, Measures: measures, Gate: gate,
		GateInfo: GateInfo{Key: gateDef.Key, Name: gateName, Source: gateSource}, Issues: counts,
		InternalIssues: issues, NewCode: NewCode{PreviousID: previousID, Counts: newCounts, Rating: NewCodeRating{Security: newRating.Security, Reliability: newRating.Reliability}},
		Delta: buildDelta(counts, measures, overallRating, in.Previous), Coverage: in.Coverage,
		Duplication: in.Duplication, Rating: overallRating,
		Hotspots: in.Hotspots, NewHotspots: in.NewHotspots,
	}, nil
}

type issueFinding struct {
	issue   Issue
	finding finding.Finding
}

func compactIssues(in []finding.Finding) ([]issueFinding, error) {
	seen := make(map[string]struct{}, len(in))
	pairs := make([]issueFinding, 0, len(in))
	for _, item := range in {
		key := finding.Identity(item)
		if key == "" {
			return nil, fmt.Errorf("finding lacks a stable identity")
		}
		if _, found := seen[key]; found {
			continue
		}
		seen[key] = struct{}{}
		item.Kind = normalizeKind(item.Kind)
		item.Severity = normalizeSeverity(item.Severity)
		item.Status = normalizeStatus(item.Status)
		pairs = append(pairs, issueFinding{issue: Issue{Key: key, Kind: item.Kind, Severity: item.Severity, Status: item.Status}, finding: item})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].issue.Key < pairs[j].issue.Key })
	return pairs, nil
}

func compactIssuesOnly(in []finding.Finding) []Issue {
	pairs, err := compactIssues(in)
	if err != nil {
		return nil
	}
	issues := make([]Issue, len(pairs))
	for i, pair := range pairs {
		issues[i] = pair.issue
	}
	return issues
}

func materiallyNew(current, previous Issue, missingPrevious bool) bool {
	if missingPrevious {
		return true
	}
	if current.Kind != previous.Kind || shared.SeverityRank(current.Severity) > shared.SeverityRank(previous.Severity) {
		return true
	}
	return (previous.Status == finding.StatusFalsePos || previous.Status == finding.StatusRemediated) &&
		current.Status != finding.StatusFalsePos && current.Status != finding.StatusRemediated
}

func normalizeKind(kind finding.Kind) finding.Kind {
	if kind == "" {
		return finding.KindSCA
	}
	return kind
}

func normalizeSeverity(severity shared.Severity) shared.Severity {
	if severity.Valid() {
		return severity
	}
	return shared.SeverityUnknown
}

func normalizeStatus(status finding.Status) finding.Status {
	if status.Valid() {
		return status
	}
	return finding.Status("unknown")
}

func countIssues(issues []Issue) Counts {
	counts := Counts{ByKind: map[string]int{}, BySeverity: map[string]int{}, ByStatus: map[string]int{}}
	for _, issue := range issues {
		counts.Total++
		counts.ByKind[string(issue.Kind)]++
		counts.BySeverity[string(issue.Severity)]++
		counts.ByStatus[string(issue.Status)]++
	}
	return counts
}

func buildMeasures(all, new Counts, overallRating rating.Report, duplication measure.DuplicationReport, coverage *measure.CoverageReport, hotspots, newHotspots hotspot.Summary) qualitygate.Snapshot {
	metrics := qualitygate.Snapshot{
		qualitygate.MetricNewIssues:       float64(new.Total),
		qualitygate.MetricNewCritical:     float64(new.BySeverity[string(shared.SeverityCritical)]),
		qualitygate.MetricNewHigh:         float64(new.BySeverity[string(shared.SeverityHigh)]),
		qualitygate.MetricNewMedium:       float64(new.BySeverity[string(shared.SeverityMedium)]),
		qualitygate.MetricTotalCritical:   float64(all.BySeverity[string(shared.SeverityCritical)]),
		qualitygate.MetricDuplicationPct:  duplication.Density(),
		qualitygate.MetricSecurityRating:  float64(gradeNumber(overallRating.Security)),
		qualitygate.MetricReliability:     float64(gradeNumber(overallRating.Reliability)),
		qualitygate.MetricMaintainability: float64(gradeNumber(overallRating.Maintainability)),
	}
	if coverage != nil {
		metrics[qualitygate.MetricCoveragePct] = coverage.Percent()
	}
	metrics[qualitygate.MetricSecurityHotspotsReviewed] = hotspots.ReviewedPct
	metrics[qualitygate.MetricNewSecurityHotspotsReviewed] = newHotspots.ReviewedPct
	metrics[qualitygate.MetricNewSecret] = float64(new.ByKind[string(finding.KindSecret)])
	for _, kind := range []finding.Kind{finding.KindSCA, finding.KindSAST, finding.KindSecret, finding.KindMisconfig, finding.KindExploitation, finding.KindDAST} {
		metrics[qualitygate.MetricNewVulnerability] += float64(new.ByKind[string(kind)])
	}
	return metrics
}

func gradeNumber(grade rating.Grade) int {
	switch grade {
	case rating.GradeA:
		return 1
	case rating.GradeB:
		return 2
	case rating.GradeC:
		return 3
	case rating.GradeD:
		return 4
	case rating.GradeE:
		return 5
	default:
		return 5
	}
}

func buildDelta(current Counts, measures qualitygate.Snapshot, currentRating rating.Report, previous *Analysis) *Delta {
	if previous == nil {
		return nil
	}
	delta := &Delta{Measures: map[string]float64{}, Ratings: map[string]int{
		"security": gradeNumber(currentRating.Security), "reliability": gradeNumber(currentRating.Reliability), "maintainability": gradeNumber(currentRating.Maintainability),
	}}
	delta.Issues = subtractCounts(current, previous.Issues)
	for metric, value := range measures {
		delta.Measures[metric] = value - previous.Measures[metric]
	}
	delta.Ratings["security"] -= gradeNumber(previous.Rating.Security)
	delta.Ratings["reliability"] -= gradeNumber(previous.Rating.Reliability)
	delta.Ratings["maintainability"] -= gradeNumber(previous.Rating.Maintainability)
	return delta
}

func subtractCounts(current, previous Counts) Counts {
	out := Counts{Total: current.Total - previous.Total, ByKind: map[string]int{}, BySeverity: map[string]int{}, ByStatus: map[string]int{}}
	for key, value := range current.ByKind {
		out.ByKind[key] = value - previous.ByKind[key]
	}
	for key, value := range previous.ByKind {
		if _, ok := out.ByKind[key]; !ok {
			out.ByKind[key] = -value
		}
	}
	for key, value := range current.BySeverity {
		out.BySeverity[key] = value - previous.BySeverity[key]
	}
	for key, value := range previous.BySeverity {
		if _, ok := out.BySeverity[key]; !ok {
			out.BySeverity[key] = -value
		}
	}
	for key, value := range current.ByStatus {
		out.ByStatus[key] = value - previous.ByStatus[key]
	}
	for key, value := range previous.ByStatus {
		if _, ok := out.ByStatus[key]; !ok {
			out.ByStatus[key] = -value
		}
	}
	return out
}
