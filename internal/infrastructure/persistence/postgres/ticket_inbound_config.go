package postgres

import (
	"context"
	"errors"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
)

var _ ports.TicketInboundConfigurationStore = (*TicketStore)(nil)

func (s *TicketStore) GetTicketInboundConfiguration(ctx context.Context, tenant, integration shared.ID) (out ports.TicketInboundConfiguration, err error) {
	if tenant.IsZero() || integration.IsZero() {
		return out, shared.ErrValidation
	}
	out.TenantID, out.IntegrationID = tenant, integration
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT enabled,integration_author,connection_revision,credential_revision,version,updated_at FROM ticket_inbound_config WHERE tenant_id=$1 AND integration_id=$2`, tenant.String(), integration.String()).Scan(&out.Enabled, &out.IntegrationAuthor, &out.ConnectionRevision, &out.CredentialRevision, &out.Version, &out.UpdatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		err = shared.ErrNotFound
	}
	return out, err
}

func (s *TicketStore) SaveTicketInboundConfiguration(ctx context.Context, tenant shared.ID, item ports.TicketInboundConfiguration, expected int) (out ports.TicketInboundConfiguration, err error) {
	if tenant.IsZero() || item.TenantID != tenant || item.IntegrationID.IsZero() || strings.TrimSpace(item.IntegrationAuthor) == "" || len(item.IntegrationAuthor) > 255 || item.ConnectionRevision < 1 || item.CredentialRevision < 0 || item.UpdatedAt.IsZero() || expected < 0 {
		return out, shared.ErrValidation
	}
	err = requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		var valid bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM integrations WHERE tenant_id=$1 AND id=$2 AND provider IN ('jira-cloud','jira-dc') AND enabled AND NOT archived AND connection_revision=$3 AND credential_revision=$4)`, tenant.String(), item.IntegrationID.String(), item.ConnectionRevision, item.CredentialRevision).Scan(&valid); e != nil {
			return e
		}
		if !valid {
			return shared.ErrConflict
		}
		var version int
		var e error
		if expected == 0 {
			e = tx.QueryRow(ctx, `INSERT INTO ticket_inbound_config(tenant_id,integration_id,enabled,integration_author,connection_revision,credential_revision,version,updated_at) VALUES($1,$2,$3,$4,$5,$6,1,$7) ON CONFLICT DO NOTHING RETURNING version`, tenant.String(), item.IntegrationID.String(), item.Enabled, item.IntegrationAuthor, item.ConnectionRevision, item.CredentialRevision, item.UpdatedAt).Scan(&version)
		} else {
			e = tx.QueryRow(ctx, `UPDATE ticket_inbound_config SET enabled=$3,integration_author=$4,connection_revision=$5,credential_revision=$6,version=version+1,updated_at=$7 WHERE tenant_id=$1 AND integration_id=$2 AND version=$8 RETURNING version`, tenant.String(), item.IntegrationID.String(), item.Enabled, item.IntegrationAuthor, item.ConnectionRevision, item.CredentialRevision, item.UpdatedAt, expected).Scan(&version)
		}
		if errors.Is(e, pgx.ErrNoRows) {
			return shared.ErrConflict
		}
		if e != nil {
			return e
		}
		out = item
		out.Version = version
		return nil
	})
	return out, ticketWriteError(err)
}
