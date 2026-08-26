package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/pythonprogram"
)

// PythonFactsProvider extracts versioned, source-only Python semantic facts from a prepared workspace.
// Implementations must never execute or import target Python. available=false means the sandboxed parser
// sidecar is absent or was built without its tree-sitter backend; callers must retain the weaker tier.
type PythonFactsProvider interface {
	PythonFacts(ctx context.Context, root string) (document pythonprogram.Document, available bool, err error)
}
