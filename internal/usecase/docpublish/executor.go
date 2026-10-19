package docpublish

import (
	"context"
	"fmt"
	domain "github.com/KKloudTarus/synapse-ce/internal/domain/docpublish"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// Executor processes already-admitted immutable artifacts. Integration-only
// workers need neither a scanner nor a report renderer to finish a release.
type Executor struct{ service *Service }

func NewExecutor(store ports.DocumentCommandStore, integrations ports.IntegrationStore, providers ProviderRegistry, authority ports.DocumentAuthorityReader, policy ports.DocumentSourceReleaseReader, audit ports.AuditLogger, clock ports.Clock) (*Executor, error) {
	if store == nil || integrations == nil || providers == nil || authority == nil || policy == nil || audit == nil || clock == nil {
		return nil, fmt.Errorf("%w: document executor dependencies required", shared.ErrValidation)
	}
	return &Executor{service: &Service{store: store, integrations: integrations, providers: providers, authority: authority, policy: policy, audit: audit, clock: clock}}, nil
}
func (e *Executor) Tick(ctx context.Context, tenant shared.ID, limit int) error {
	return e.service.Tick(ctx, tenant, limit)
}
func (e *Executor) Execute(ctx context.Context, tenant, id shared.ID) (domain.Intent, error) {
	return e.service.Execute(ctx, tenant, id)
}
