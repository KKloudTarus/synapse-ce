package integrations

import (
	"context"
	"fmt"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TicketProvider resolves the shared registry capability behind the existing vault
// boundary. Every call binds the authoritative connection and credential revisions.
func (service *Service) TicketProvider(ctx context.Context, item integration.Integration) (ports.TicketProvider, error) {
	tenant, ok := shared.TenantFrom(ctx)
	if !ok || tenant.IsZero() || item.TenantID != tenant {
		return nil, shared.ErrValidation
	}
	current, err := service.store.GetIntegration(ctx, item.ID)
	if err != nil {
		return nil, err
	}
	if current.Archived || current.Endpoint != item.Endpoint || current.Provider != item.Provider || current.ConnectionRevision != item.ConnectionRevision || current.CredentialRevision != item.CredentialRevision || (item.Enabled && !current.Enabled) {
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
	provider, ok := adapter.(ports.TicketProvider)
	if !ok {
		return nil, fmt.Errorf("%w: integration does not support tickets", shared.ErrValidation)
	}
	// SCM-backed ticket providers keep no second credential store. Bind the
	// current connector token only long enough for preview payload redaction;
	// each request resolves it again immediately before I/O.
	if binder, ok := provider.(interface{ BindTicketCredentials(context.Context) error }); ok {
		if err := binder.BindTicketCredentials(ctx); err != nil {
			return nil, err
		}
	}
	return provider, nil
}

// TicketProviderDescriptor exposes code-owned ticket capability metadata to the
// ticket workflow. Runtime integrations can select only registered providers.
func (service *Service) TicketProviderDescriptor(provider integration.Provider) (integration.ProviderDescriptor, error) {
	return service.registry.Descriptor(provider)
}
