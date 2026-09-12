package rustsymreach

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/srcimports"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type rustSymbolScannerAdapter struct{}

func (rustSymbolScannerAdapter) ScanSymbols(ctx context.Context, dir string) (ports.RustSymbolIndex, error) {
	return srcimports.NewRustSymbolScanner().ScanSymbols(ctx, dir)
}
