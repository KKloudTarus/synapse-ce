package postgres

import (
	"context"
	"errors"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/ticketing"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

var _ ports.TicketRequestReader = (*TicketStore)(nil)

func (s *TicketStore) FindTicketRequest(ctx context.Context, tenant, mapping, engagement, finding shared.ID, key string) (out ticketing.Intent, found bool, err error) {
	if tenant.IsZero() || mapping.IsZero() || engagement.IsZero() || finding.IsZero() || key == "" || len(key) > 128 {
		return out, false, shared.ErrValidation
	}
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		var e error
		out, e = scanTicketIntent(tx.QueryRow(ctx, `SELECT `+intentCols+` FROM ticket_intents WHERE tenant_id=$1 AND mapping_id=$2 AND engagement_id=$3 AND finding_id=$4 AND request_key=$5 AND integration_id=(SELECT integration_id FROM ticket_mappings WHERE tenant_id=$1 AND id=$2)`, tenant.String(), mapping.String(), engagement.String(), finding.String(), key))
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		found = e == nil
		return e
	})
	return out, found, ticketWriteError(err)
}
