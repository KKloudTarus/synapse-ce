package integrations

import (
	"context"
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func (service *Service) DocumentProvider(ctx context.Context, item integration.Integration) (ports.DocumentProvider, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() || item.TenantID != tenant {
		return nil, shared.ErrValidation
	}
	current, err := service.store.GetIntegration(ctx, item.ID)
	if err != nil {
		return nil, err
	}
	if current.Archived || !current.Enabled || current.Endpoint != item.Endpoint || current.Provider != item.Provider || current.ConnectionRevision != item.ConnectionRevision || current.CredentialRevision != item.CredentialRevision {
		return nil, shared.ErrConflict
	}
	credentials, err := service.credentials(ctx, current.ID, current.CredentialRevision)
	if err != nil {
		return nil, err
	}
	adapter, err := service.registry.Resolve(current, credentials)
	if err != nil {
		return nil, err
	}
	provider, ok := adapter.(ports.DocumentProvider)
	if !ok {
		if closer, ok := adapter.(interface{ Close() }); ok {
			closer.Close()
		}
		return nil, fmt.Errorf("%w: integration does not support document publication", shared.ErrValidation)
	}
	return provider, nil
}
