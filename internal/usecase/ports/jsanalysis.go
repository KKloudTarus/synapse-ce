package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsprogram"
)

// JsFactsProvider extracts versioned, source-only JavaScript/TypeScript semantic facts from a prepared
// workspace. Implementations must never execute or import target JS. available=false means the sandboxed
// parser sidecar is absent or was built without its tree-sitter backend; callers must retain the weaker tier.
type JsFactsProvider interface {
	JsFacts(ctx context.Context, root string) (document jsprogram.Document, available bool, err error)
}
