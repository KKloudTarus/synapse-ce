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
	credentials, err := service.credentials(ctx, current.ID, current.CredentialRevision)
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
	return provider, nil
}
