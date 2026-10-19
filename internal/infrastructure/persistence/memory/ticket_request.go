package memory

import (
	"context"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

var _ ports.TicketRequestReader = (*TicketStore)(nil)

func (s *TicketStore) FindTicketRequest(ctx context.Context, tenant, mapping, engagement, finding shared.ID, key string) (ticketing.Intent, bool, error) {
	if err := ctx.Err(); err != nil {
		return ticketing.Intent{}, false, err
	}
	if tenant.IsZero() || mapping.IsZero() || engagement.IsZero() || finding.IsZero() || key == "" || len(key) > 128 {
		return ticketing.Intent{}, false, shared.ErrValidation
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, i := range s.intents[tenant] {
		if i.MappingID == mapping && i.EngagementID == engagement && i.FindingID == finding && i.RequestKey == key {
			return i.Clone(), true, nil
		}
	}
	return ticketing.Intent{}, false, nil
}
