package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// CodeAnalysisRawFinding is one deterministic source issue located at a source file:line before promotion
// to a finding.Finding. Kind is "quality", "reliability", or "sast".
type CodeAnalysisRawFinding struct {
	Kind        string // "quality" | "reliability" | "sast"
	RuleID      string
	CWE         string
	Severity    shared.Severity
	Title       string
	Description string
	File        string // path relative to the scanned root
	Line        int    // 1-based
}

// CodeAnalyzer runs deterministic maintainability/reliability rules over a local source tree. It reads the
// tree only (never executes it) and honors context cancellation.
type CodeAnalyzer interface {
	Analyze(ctx context.Context, root string) ([]CodeAnalysisRawFinding, error)
}
