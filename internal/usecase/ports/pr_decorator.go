package ports

import (
	"context"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/qualitygate"
)

// PRDecorationTarget identifies the forge change that should receive an analysis result.
// PullRequest is provider-neutral: it is a GitHub/Bitbucket PR number or a GitLab MR IID.
type PRDecorationTarget struct {
	Repository   string
	CommitSHA    string
	PullRequest  string
	TargetBranch string
}

// Complete reports whether enough forge identity is present to decorate a pull request safely.
// A partial target is deliberately skipped instead of guessing where an outward write belongs.
func (t PRDecorationTarget) Complete() bool {
	return strings.TrimSpace(t.Repository) != "" &&
		strings.TrimSpace(t.CommitSHA) != "" &&
		strings.TrimSpace(t.PullRequest) != "" &&
		strings.TrimSpace(t.TargetBranch) != ""
}

// PRDecoration is provider-agnostic render data. Credentials are intentionally absent: adapters
// receive authentication through their own server-side configuration and must never render it.
type PRDecoration struct {
	Target      PRDecorationTarget
	Gate        qualitygate.Result
	Summary     string
	Annotations []projectanalysis.Annotation
}

// PRDecorator publishes one quality-gate result to a forge. Implementations are expected to update
// existing outward state idempotently; callers treat errors as fail-soft and never fail the scan.
type PRDecorator interface {
	Decorate(context.Context, PRDecoration) error
}
