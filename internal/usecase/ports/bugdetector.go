package ports

import "context"

// BugFinding is one deterministic reliability defect from the deeper (AST dataflow) bug detection: a rule
// id, a human message, and the source file:line. Kind is always reliability.
type BugFinding struct {
	Rule    string
	Message string
	File    string
	Line    int
}

// BugDetector runs the deeper, AST-based reliability checks (unreachable code, constant conditions, ...)
// over a source tree via the sandboxed synapse-ast sidecar. available=false when no AST backend is
// built/wired (a CGO-free build), so a caller degrades rather than failing.
type BugDetector interface {
	Bugs(ctx context.Context, root string) (findings []BugFinding, available bool, err error)
}
