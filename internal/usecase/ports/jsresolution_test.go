package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

type compileTimeJSImportResolver struct{}

func (compileTimeJSImportResolver) Resolve(context.Context, string, modulegraph.Graph, *sbom.SBOM) (jsresolution.Result, error) {
	return jsresolution.Result{}, nil
}

var _ JSImportResolver = compileTimeJSImportResolver{}
