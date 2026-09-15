package projectuc

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
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

	coverage := "n/a"
	if analysis.Coverage != nil {
		coverage = fmt.Sprintf("%.1f%%", analysis.Coverage.Percent())
	}
	scope := fmt.Sprintf("pull request #%s → %s", target.PullRequest, target.TargetBranch)
	summary := qualitygate.RenderMarkdown(scope, analysis.Rating, analysis.Duplication.Density(), coverage, analysis.Gate)
	annotations := append([]projectanalysis.Annotation(nil), analysis.Annotations...)
	if err := s.decorator.Decorate(ctx, ports.PRDecoration{
		Target:      target,
		Gate:        analysis.Gate,
		Summary:     summary,
		Annotations: annotations,
	}); err != nil {
		slog.Warn("project analysis PR decoration failed; analysis result is unchanged")
	}
}
