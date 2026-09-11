package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/javaprogram"
)

// JavaFactsProvider extracts versioned, source-only Java semantic facts from a prepared workspace.
// Implementations must never execute or import target Java. available=false means the sandboxed parser
// sidecar is absent or was built without its tree-sitter backend; callers must retain the weaker tier.
type JavaFactsProvider interface {
	JavaFacts(ctx context.Context, root string) (document javaprogram.Document, available bool, err error)
}
