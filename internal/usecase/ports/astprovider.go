package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
)

// ASTProvider computes structural facts over a source tree using a language-aware parser, backed by the
// sandboxed synapse-ast sidecar (which isolates the CGO tree-sitter grammars out of the server/CLI, the
// way synapse-callgraph isolates go/ssa). Its first capability is accurate per-language function counts.
//
// available=false means no AST backend is wired or built (for example a CGO-disabled build where the
// sidecar is the stub), so a caller falls back to its own counting and reports "not counted" rather than
// a wrong zero. Implementations read the target only (never execute it) and honor context cancellation.
type ASTProvider interface {
	FunctionCounts(ctx context.Context, root string) (counts map[string]int, available bool, err error)
}

// CodeMetricsProvider computes per-function complexity (cyclomatic + cognitive) over a source tree, via
// the same sandboxed synapse-ast sidecar. available=false when no AST backend is built/wired, so a caller
// degrades (e.g. skips the complexity gate) rather than failing.
type CodeMetricsProvider interface {
	Complexity(ctx context.Context, root string) (report measure.ComplexityReport, available bool, err error)
}
