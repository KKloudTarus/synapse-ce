package ports

import (
	"context"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
)

type compileTimeJSImportScanner struct{}

func (compileTimeJSImportScanner) Scan(context.Context, string) (modulegraph.Graph, error) {
	return modulegraph.Graph{}, nil
}

func TestJSImportScannerContract(t *testing.T) {
	t.Parallel()
	var scanner JSImportScanner = compileTimeJSImportScanner{}
	if scanner == nil {
		t.Fatal("scanner is nil")
	}
}
