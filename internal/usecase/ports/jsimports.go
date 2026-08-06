package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
)

// JSImportScanner builds a deterministic, source-only JavaScript and TypeScript
// module graph beneath root.
//
// Implementations must not execute project code, package managers, bundlers, or
// lifecycle scripts; must not access the network; must honor context
// cancellation; and must surface incomplete observation as structured coverage
// issues rather than silently converting unknown behavior into a negative.
type JSImportScanner interface {
	Scan(ctx context.Context, root string) (modulegraph.Graph, error)
}
