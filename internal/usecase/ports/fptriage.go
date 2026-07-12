package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
)

// SourceSnippetReader returns a small source excerpt around file:line (1-based, radius lines each side)
// from a workspace. The concrete implementation reads the Synapse-controlled scanned tree (a bounded,
// read-only helper), so this is not a path handed to a tool. An error (missing/binary file) is
// non-fatal — the caller critiques on finding metadata alone.
type SourceSnippetReader interface {
	Snippet(ctx context.Context, file string, line, radius int) (string, error)
}

// AICritique is one finding's LLM false-positive verdict (propose-only, advisory). Verdict and Driver use
// the closed judgment.CritiqueClaim vocabulary (no free prose). SuspectedFP is set when a "refuted"
// verdict clears the confidence bar — and, when a distinct verifier is configured, it independently
// confirmed. It is retain-and-mark: a suspected-FP finding stays reported and sealed and is only held
// back from the CI gate, never deleted.
type AICritique struct {
	FindingID   string `json:"finding_id"`
	DedupKey    string `json:"dedup_key"`
	Verdict     string `json:"verdict"`
	Driver      string `json:"driver"`
	Confidence  int    `json:"confidence"`
	SuspectedFP bool   `json:"suspected_fp"`
	// Verified is true when a DISTINCT verifier model independently confirmed the refutation (two-model
	// consensus). Omitted when no verifier was configured (single-model triage).
	Verified bool `json:"verified,omitempty"`
}

// FPTriager runs an LLM false-positive critique over candidate findings from a workspace and returns a
// per-candidate advisory verdict. It is best-effort and PROPOSE-ONLY: it never mutates or deletes a
// finding; the caller applies a suspected-FP as retain-and-mark (held back from the --fail-on gate,
// still reported and evidence-sealed). Injected optionally into the scan pipeline; nil = no triage.
type FPTriager interface {
	Triage(ctx context.Context, candidates []finding.Finding, workspaceDir string) []AICritique
}
