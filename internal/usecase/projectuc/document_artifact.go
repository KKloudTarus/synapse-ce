package projectuc

import (
	"context"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ReadProjectQualitySummary implements ports.ProjectQualitySummaryReader. It uses
// the same selected analysis as Overview and binds the projection to that immutable
// analysis plus its persisted source-manifest digest.
func (s *Service) ReadProjectQualitySummary(ctx context.Context, tenantID, projectID shared.ID) (ports.ProjectQualitySummary, error) {
	if tenantID.IsZero() || projectID.IsZero() || s.repo == nil || s.analyses == nil {
		return ports.ProjectQualitySummary{}, fmt.Errorf("%w: project quality document source is not configured", shared.ErrValidation)
	}
	project, err := s.repo.GetByID(ctx, tenantID, projectID)
	if err != nil {
		return ports.ProjectQualitySummary{}, fmt.Errorf("read project quality source: %w", err)
	}
	if project == nil || project.ID != projectID || project.TenantID != tenantID {
		return ports.ProjectQualitySummary{}, shared.ErrNotFound
	}
	overview, err := s.Overview(ctx, tenantID, project.Key, "")
	if err != nil {
		return ports.ProjectQualitySummary{}, fmt.Errorf("read project quality overview: %w", err)
	}
	if overview.State != OverviewStateAnalyzed || overview.LatestAnalysis == nil {
		return ports.ProjectQualitySummary{}, fmt.Errorf("%w: project has no completed analysis to publish", shared.ErrValidation)
	}
	analysis, ok, err := s.overviewLatestAnalysis(ctx, tenantID, projectID, "")
	if err != nil {
		return ports.ProjectQualitySummary{}, fmt.Errorf("read selected project analysis: %w", err)
	}
	if !ok || analysis.ID != overview.LatestAnalysis.ID || analysis.TenantID != tenantID.String() || analysis.ProjectID != projectID.String() || analysis.CreatedAt.IsZero() {
		return ports.ProjectQualitySummary{}, fmt.Errorf("%w: project quality analysis ownership mismatch", shared.ErrValidation)
	}
	head, err := qualitySourceHead(analysis)
	if err != nil {
		return ports.ProjectQualitySummary{}, err
	}
	return ports.ProjectQualitySummary{
		TenantID:          tenantID,
		ProjectID:         projectID,
		Title:             "Project quality summary: " + overview.Project.Name,
		Paragraphs:        qualitySummaryParagraphs(overview, analysis, head),
		EvidenceHead:      "",
		SourceRevision:    "analysis:" + analysis.ID + ":" + head,
		GeneratedAt:       analysis.CreatedAt.UTC(),
		IntegrityVerified: true,
	}, nil
}

func qualitySourceHead(analysis projectanalysis.Analysis) (string, error) {
	head := analysis.SourceManifest.ArtifactDigest()
	if !validQualityManifestDigest(analysis.SourceManifest.Digest) || analysis.SourceManifest.Digest != head {
		return "", fmt.Errorf("%w: project analysis source manifest integrity failed", shared.ErrValidation)
	}
	return head, nil
}

func validQualityManifestDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, r := range value[len("sha256:"):] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func qualitySummaryParagraphs(overview Overview, analysis projectanalysis.Analysis, head string) []string {
	paragraphs := []string{
		"Project key: " + overview.Project.Key,
		"Selected analysis: " + analysis.ID,
		"Analysis time: " + analysis.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"),
		"Source manifest digest: " + head,
		"Quality gate: " + qualityGateText(overview.Gate),
		"Overall security: " + ratingMetricText(overview.Overall.Security),
		"Overall reliability: " + ratingMetricText(overview.Overall.Reliability),
		"Overall maintainability: " + ratingMetricText(overview.Overall.Maintainability),
		"Overall coverage: " + percentageMetricText(overview.Overall.Coverage),
		"Overall duplications: " + percentageMetricText(overview.Overall.Duplications),
		"Security hotspots reviewed: " + percentageMetricText(overview.Overall.SecurityHotspotsReviewed),
		"New-code security: " + ratingMetricText(overview.NewCode.Security),
		"New-code reliability: " + ratingMetricText(overview.NewCode.Reliability),
		"New-code maintainability: " + ratingMetricText(overview.NewCode.Maintainability),
		"New-code issues: " + countMetricText(overview.IssueSummary.NewCodeTotal),
	}
	if ref := strings.TrimSpace(analysis.SourceRef); ref != "" {
		paragraphs = append(paragraphs, "Source reference: "+ref)
	}
	if commit := strings.TrimSpace(analysis.SourceCommit); commit != "" {
		paragraphs = append(paragraphs, "Source commit: "+commit)
	}
	if overview.Gate != nil {
		for i, condition := range overview.Gate.FailedConditions {
			if i == 24 { // Keep the provider page and PDF projection bounded.
				paragraphs = append(paragraphs, fmt.Sprintf("Additional failed gate conditions: %d", len(overview.Gate.FailedConditions)-i))
				break
			}
			if condition.Unmeasured {
				paragraphs = append(paragraphs, "Gate condition "+condition.Metric+": unavailable")
				continue
			}
			paragraphs = append(paragraphs, fmt.Sprintf("Gate condition %s %s %.4g (actual %.4g)", condition.Metric, condition.Operator, condition.Threshold, condition.Actual))
		}
	}
	return paragraphs
}

func qualityGateText(gate *OverviewGate) string {
	if gate == nil {
		return "unavailable"
	}
	text := string(gate.Status)
	if gate.Name != nil && strings.TrimSpace(*gate.Name) != "" {
		text += " (" + strings.TrimSpace(*gate.Name) + ")"
	}
	return text
}

func ratingMetricText(metric RatingMetric) string {
	if metric.Availability == MetricAvailable && metric.Grade != nil {
		return string(*metric.Grade)
	}
	return unavailableMetricText(string(metric.Availability), metric.UnavailableReason)
}

func percentageMetricText(metric PercentageMetric) string {
	if metric.Availability == MetricAvailable && metric.Value != nil {
		return fmt.Sprintf("%.2f%%", *metric.Value)
	}
	return unavailableMetricText(string(metric.Availability), metric.UnavailableReason)
}

func countMetricText(metric CountMetric) string {
	if metric.Availability == MetricAvailable && metric.Value != nil {
		return fmt.Sprintf("%d", *metric.Value)
	}
	return unavailableMetricText(string(metric.Availability), metric.UnavailableReason)
}

func unavailableMetricText(availability string, reason *UnavailableReason) string {
	if reason != nil {
		return availability + " (" + string(*reason) + ")"
	}
	return availability
}

var _ ports.ProjectQualitySummaryReader = (*Service)(nil)
