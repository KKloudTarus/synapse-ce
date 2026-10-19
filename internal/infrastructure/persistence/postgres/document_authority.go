package postgres

import (
	"context"
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DocumentAuthorityReader struct{ pool *pgxpool.Pool }

var _ ports.DocumentAuthorityReader = (*DocumentAuthorityReader)(nil)

func NewDocumentAuthorityReader(pool *pgxpool.Pool) (*DocumentAuthorityReader, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: document authority requires PostgreSQL", shared.ErrValidation)
	}
	return &DocumentAuthorityReader{pool: pool}, nil
}
func (s *DocumentAuthorityReader) CanReleaseDocument(ctx context.Context, tenant shared.ID, actor ports.DocumentActor) (bool, error) {
	if tenant.IsZero() || actor.UserID.IsZero() {
		return false, shared.ErrForbidden
	}
	var allowed bool
	err := requireTenant(ctx, s.pool, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT synapse_can_release_document($1,$2,$3,$4)`, tenant.String(), actor.UserID.String(), actor.MembershipID.String(), actor.PersonID.String()).Scan(&allowed)
	})
	if err != nil {
		return false, fmt.Errorf("check current document authority: %w", err)
	}
	return allowed, nil
}
