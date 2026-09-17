package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/scmdecoration"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// buildGateDecorator constructs the CLI PR decorator when --decorate (or --dry-run) is set. It returns
// (nil, nil) when decoration was not requested, so the caller stays a no-op by default. The forge is the
// CI context's own provider claim; the token comes from SYNAPSE_DECORATION_TOKEN (with an optional
// SYNAPSE_DECORATION_USERNAME for Bitbucket Basic auth). --dry-run needs no token: it previews the target
// and gate verdict without any network write, so a pipeline can confirm the decoration will land before
// a credential is provisioned.
func buildGateDecorator(getenv func(string) string, decorate, dryRun bool) (ports.PRDecorator, error) {
	if !decorate && !dryRun {
		return nil, nil
	}
	ci, err := ciContextFromEnv(projectanalysis.CIContext{}, getenv).Normalize()
	if err != nil {
		return nil, fmt.Errorf("read CI context: %w", err)
	}
	if strings.TrimSpace(ci.Provider) == "" {
		return nil, fmt.Errorf("--decorate: no CI provider detected; set SYNAPSE_CI_PROVIDER to one of %s", strings.Join(scmdecoration.SupportedProviders(), ", "))
	}
	host, ok := scmdecoration.CredentialHostForProvider(ci.Provider)
	if !ok {
		return nil, fmt.Errorf("--decorate: unsupported provider %q (want one of %s)", ci.Provider, strings.Join(scmdecoration.SupportedProviders(), ", "))
	}
	if dryRun {
		return &dryRunDecorator{out: os.Stdout, provider: ci.Provider}, nil
	}
	token := strings.TrimSpace(getenv("SYNAPSE_DECORATION_TOKEN"))
	if token == "" {
		return nil, fmt.Errorf("--decorate: SYNAPSE_DECORATION_TOKEN is not set")
	}
	resolver, err := scmdecoration.NewStaticCredentialResolver(host, strings.TrimSpace(getenv("SYNAPSE_DECORATION_USERNAME")), []byte(token))
	if err != nil {
		return nil, err
	}
	return scmdecoration.ForProvider(ci.Provider, resolver)
}

// dryRunDecorator prints what would be posted and performs no network write, so --dry-run is safe to run
// on any pipeline. It is intentionally terse and never prints the summary body, only the resolved target.
type dryRunDecorator struct {
	out      io.Writer
	provider string
}

func (d *dryRunDecorator) Decorate(_ context.Context, decoration ports.PRDecoration) error {
	verdict := "FAILED"
	if decoration.Gate.Passed {
		verdict = "PASSED"
	}
	_, _ = fmt.Fprintf(d.out, "[decorate dry-run] provider=%s repo=%s pr=%s head=%s target=%s gate=%s annotations=%d\n",
		d.provider, decoration.Target.Repository, decoration.Target.PullRequest, decoration.Target.CommitSHA,
		decoration.Target.TargetBranch, verdict, len(decoration.Annotations))
	return nil
}

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
