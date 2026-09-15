package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
)

// CouplingAnalyzer builds a bounded, deterministic graph of first-party source
// modules. Implementations must not execute project code or access the network.
type CouplingAnalyzer interface {
	AnalyzeCoupling(ctx context.Context, root string) (measure.CouplingReport, error)
}
