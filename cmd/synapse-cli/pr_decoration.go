package main

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// cliPRDecorator is the composition seam #1125 will populate with a provider adapter. Keeping the
// foundation nil by default means #1121 introduces no forge network traffic on its own.
var cliPRDecorator ports.PRDecorator

// triggerGateDecorationFromEnv runs at the end of a local gate evaluation. Decoration is fail-soft:
// the gate's own exit status remains authoritative even when an outward write cannot be made.
func triggerGateDecorationFromEnv(ctx context.Context, decorator ports.PRDecorator, result qualitygate.Result, summary string, findings []finding.Finding) {
	if decorator == nil {
		return
	}
	ci, err := ciContextFromEnv(projectanalysis.CIContext{}, os.Getenv).Normalize()
	if err != nil {
		return
	}
	target := ports.PRDecorationTarget{
		Repository:   ci.RepoSlug,
		CommitSHA:    ci.HeadSHA,
		PullRequest:  ci.PullRequest,
		TargetBranch: ci.TargetBranch,
	}
	if !target.Complete() {
		return
	}
	annotations := make([]projectanalysis.Annotation, 0, len(findings))
	for _, item := range findings {
		location := item.SourceLocation
		if location == nil || location.Validate() != nil {
			if file, line, ok := qualitygate.FileLineOf(item.DedupKey); ok {
				location = &finding.SourceLocation{File: file, StartLine: line, EndLine: line}
			}
		}
		if location == nil || location.Validate() != nil {
			continue
		}
		message := item.Description
		if message == "" {
			message = item.Title
		}
		annotations = append(annotations, projectanalysis.Annotation{
			FindingKey: finding.Identity(item), RuleKey: item.RuleKey, Message: message,
			Kind: item.Kind, Severity: item.Severity, Status: item.Status, Location: *location,
		})
	}
	if err := decorator.Decorate(ctx, ports.PRDecoration{Target: target, Gate: result, Summary: summary, Annotations: annotations}); err != nil {
		slog.Warn("PR decoration failed; quality gate result is unchanged")
	}
}

// prBaseRef resolves the new-code diff base for a scan. An explicit --base always wins. Otherwise a
// pull-request scan (PR number + target branch both known from CI) defaults to the merge target branch
// as origin/<target>, so new code is scoped to what the PR changes relative to where it will merge.
// An image scan, or a non-PR scan, keeps the given base unchanged.
func prBaseRef(baseRef string, image bool, ci projectanalysis.CIContext) string {
	if strings.TrimSpace(baseRef) != "" || image {
		return baseRef
	}
	if strings.TrimSpace(ci.PullRequest) != "" && strings.TrimSpace(ci.TargetBranch) != "" {
		return "origin/" + strings.TrimSpace(ci.TargetBranch)
	}
	return baseRef
}
