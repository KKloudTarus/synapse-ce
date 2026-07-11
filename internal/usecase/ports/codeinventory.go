package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
)

// CodeInventoryScanner computes a per-language code-size inventory (files, code/comment/blank lines,
// and functions where a parser exists) over a local source tree. It is the first producer of the
// code-quality ("power tool") capability. Implementations read the tree only (never execute it) and
// must honor context cancellation.
type CodeInventoryScanner interface {
	Inventory(ctx context.Context, root string) (measure.Inventory, error)
}
