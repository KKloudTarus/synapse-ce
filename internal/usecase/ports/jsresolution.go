package ports

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/modulegraph"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// JSImportResolver resolves external JS/TS module specifiers to deterministic
// package identities without making reachability judgments.
//
// Implementations must remain offline, must not execute Node.js, package
// managers, bundlers, lifecycle scripts, or project configuration, and must
// preserve unresolved or ambiguous identities as explicit incomplete coverage.
type JSImportResolver interface {
	Resolve(ctx context.Context, root string, graph modulegraph.Graph, doc *sbom.SBOM) (jsresolution.Result, error)
}
