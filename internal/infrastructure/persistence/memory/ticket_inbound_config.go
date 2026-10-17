package memory

import (
	"context"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.TicketInboundConfigurationStore = (*TicketStore)(nil)

func (s *TicketStore) GetTicketInboundConfiguration(ctx context.Context, tenant, integration shared.ID) (ports.TicketInboundConfiguration, error) {
	if err := ctx.Err(); err != nil {
		return ports.TicketInboundConfiguration{}, err
	}
	if tenant.IsZero() || integration.IsZero() {
		return ports.TicketInboundConfiguration{}, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out, ok := s.inboundConfigurations[tenant][integration]
	if !ok {
		return out, shared.ErrNotFound
	}
	return out, nil
}

func (s *TicketStore) SaveTicketInboundConfiguration(ctx context.Context, tenant shared.ID, item ports.TicketInboundConfiguration, expected int) (ports.TicketInboundConfiguration, error) {
	if err := ctx.Err(); err != nil {
		return ports.TicketInboundConfiguration{}, err
	}
	if tenant.IsZero() || item.TenantID != tenant || item.IntegrationID.IsZero() || strings.TrimSpace(item.IntegrationAuthor) == "" || len(item.IntegrationAuthor) > 255 || item.ConnectionRevision < 1 || item.CredentialRevision < 0 || item.UpdatedAt.IsZero() || expected < 0 {
		return ports.TicketInboundConfiguration{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.inboundConfigurations[tenant][item.IntegrationID]
	if current.Version != expected {
		return ports.TicketInboundConfiguration{}, shared.ErrConflict
	}
	if s.inboundConfigurations == nil {
		s.inboundConfigurations = make(map[shared.ID]map[shared.ID]ports.TicketInboundConfiguration)
	}
	if s.inboundConfigurations[tenant] == nil {
		s.inboundConfigurations[tenant] = make(map[shared.ID]ports.TicketInboundConfiguration)
	}
	item.Version = expected + 1
	s.inboundConfigurations[tenant][item.IntegrationID] = item
	return item, nil
}
