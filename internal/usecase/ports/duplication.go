package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
)

// DuplicationScanner detects copy-paste (duplicated token runs) over a local source tree and returns the
// standard duplication metrics. Implementations read the tree only (never execute it) and honor context
// cancellation.
type DuplicationScanner interface {
	Duplication(ctx context.Context, root string) (measure.DuplicationReport, error)
}
