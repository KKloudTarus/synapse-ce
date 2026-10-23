package integrations

import (
	"context"
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func (service *Service) documentAdapter(ctx context.Context, item integration.Integration) (integration.Adapter, error) {
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
	credentials, err := service.providerCredentials(ctx, current, current.CredentialRevision)
	if err != nil {
		return nil, err
	}
	adapter, err := service.registry.Resolve(current, credentials)
	if err != nil {
		return nil, err
	}
	return adapter, nil
}

func (service *Service) DocumentProvider(ctx context.Context, item integration.Integration) (ports.DocumentProvider, error) {
	adapter, err := service.documentAdapter(ctx, item)
	if err != nil {
		return nil, err
	}
	provider, ok := adapter.(ports.DocumentProvider)
	if !ok {
		closeDocumentAdapter(adapter)
		return nil, fmt.Errorf("%w: integration does not support document publication", shared.ErrValidation)
	}
	return provider, nil
}

func (service *Service) DocumentReleasePreflighter(ctx context.Context, item integration.Integration) (ports.DocumentReleasePreflighter, error) {
	adapter, err := service.documentAdapter(ctx, item)
	if err != nil {
		return nil, err
	}
	preflight, ok := adapter.(ports.DocumentReleasePreflighter)
	if !ok {
		closeDocumentAdapter(adapter)
		return nil, nil
	}
	return preflight, nil
}

func closeDocumentAdapter(adapter integration.Adapter) {
	if closer, ok := adapter.(interface{ Close() }); ok {
		closer.Close()
	}
}
