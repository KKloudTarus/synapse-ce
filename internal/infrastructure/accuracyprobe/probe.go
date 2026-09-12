// Package accuracyprobe adapts the owned advisory-matching engine (ownadvisory.Source) into the
// accuracyeval.CaseScanner the usecase-layer accuracy evaluation needs. It builds a per-case advisory
// store from the case's pinned advisories and runs the engine over it, entirely offline. Keeping this
// here (infrastructure) lets internal/usecase/accuracyeval stay free of any infrastructure import.
package accuracyprobe

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownadvisory"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/accuracyeval"
)

// Probe runs the owned engine over a single accuracy case.
type Probe struct{}

// New returns a Probe.
func New() *Probe { return &Probe{} }

var _ accuracyeval.CaseScanner = (*Probe)(nil)

// ScanCase loads the case advisories into the production in-memory advisory store (the twin of the
// Postgres repository, so ByPackage keying and ordering match what detection sees in production) and
// runs the owned engine over the case SBOM.
func (p *Probe) ScanCase(ctx context.Context, advisories []advisory.Advisory, doc *sbom.SBOM) ([]vulnerability.RawFinding, error) {
	store := memory.NewAdvisoryStore()
	for _, a := range advisories {
		if err := store.Upsert(ctx, a); err != nil {
			return nil, err
		}
	}
	return ownadvisory.New(store).Scan(ctx, doc)
}
