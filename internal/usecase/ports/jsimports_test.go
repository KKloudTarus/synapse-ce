package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
)

type compileTimeJSImportScanner struct{}

func (compileTimeJSImportScanner) Scan(context.Context, string) (modulegraph.Graph, error) {
	return modulegraph.Graph{}, nil
}

var _ JSImportScanner = compileTimeJSImportScanner{}
