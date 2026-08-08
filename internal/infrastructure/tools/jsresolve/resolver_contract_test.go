package jsresolve_test

import (
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/jsresolve"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.JSImportResolver = (*jsresolve.Resolver)(nil)
