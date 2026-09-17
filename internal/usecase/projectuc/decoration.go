package projectuc

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// decorateProjectAnalysis is deliberately fail-soft: persistence and the quality-gate verdict are
// authoritative, while forge write-back is an outward convenience. A missing/partial PR identity is
// skipped rather than guessed, and an adapter error can never turn a completed analysis into a failure.
func (s *Service) decorateProjectAnalysis(ctx context.Context, analysis projectanalysis.Analysis) {
	if s.decorator == nil || analysis.CI == nil {
		return
	}
	target := ports.PRDecorationTarget{
		Repository:   analysis.CI.RepoSlug,
		CommitSHA:    analysis.CI.HeadSHA,
		PullRequest:  analysis.CI.PullRequest,
		TargetBranch: analysis.CI.TargetBranch,
	}
	if !target.Complete() {
		return
	}
	// Opt-in per project: decorate only when the project has enabled it. A lookup failure is fail-soft
	// (the analysis is already persisted) and is treated as not-opted-in so a transient read never writes.
	tenantID, projectID := shared.ID(analysis.TenantID), shared.ID(analysis.ProjectID)
	if tenantID.IsZero() || projectID.IsZero() {
		return
	}
	proj, err := s.repo.GetByID(ctx, tenantID, projectID)
	if err != nil || proj == nil || !proj.DecoratePullRequests {
		return
	}

	coverage := "n/a"
	if analysis.Coverage != nil {
		coverage = fmt.Sprintf("%.1f%%", analysis.Coverage.Percent())
	}
	scope := fmt.Sprintf("pull request #%s → %s", target.PullRequest, target.TargetBranch)
	summary := qualitygate.RenderMarkdown(scope, analysis.Rating, analysis.Duplication.Density(), coverage, analysis.Gate)
	annotations := append([]projectanalysis.Annotation(nil), analysis.Annotations...)
	fileChanges := append([]projectanalysis.FileChange(nil), analysis.FileChanges...)
	newIssues := analysis.NewCode.Counts.Total
	var newCoverage *float64
	newCoverageReason := analysis.Snapshot.NewCodeCoverage.Reason
	if analysis.Snapshot.NewCodeCoverage.Availability == measure.AvailabilityAvailable && analysis.Snapshot.NewCodeCoverage.Value != nil {
		value := *analysis.Snapshot.NewCodeCoverage.Value
		newCoverage = &value
		newCoverageReason = ""
	}
	if err := s.decorator.Decorate(ctx, ports.PRDecoration{
		Provider: analysis.CI.Provider,
		Target:   target, Gate: analysis.Gate, Summary: summary, Annotations: annotations, FileChanges: fileChanges,
		NewIssues: &newIssues, NewCoverage: newCoverage, NewCoverageReason: newCoverageReason,
	}); err != nil {
		slog.Warn("project analysis PR decoration failed; analysis result is unchanged")
	}
}
