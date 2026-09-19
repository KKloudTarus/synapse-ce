package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// PlatformPersonIndex is a privileged, exact-person platform surface used only to fan a global
// person mutation into organizations that already own a membership. It accepts no tenant wildcard,
// role, display-name or contact query.
type PlatformPersonIndex struct{ pool *pgxpool.Pool }

func NewPlatformPersonIndex(pool *pgxpool.Pool) (*PlatformPersonIndex, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: platform person index requires pool", shared.ErrValidation)
	}
	return &PlatformPersonIndex{pool: pool}, nil
}

var _ ports.PlatformPersonIndex = (*PlatformPersonIndex)(nil)

func (s *PlatformPersonIndex) OrganizationsForExactPerson(ctx context.Context, personID shared.ID) ([]shared.ID, error) {
	if personID.IsZero() {
		return nil, fmt.Errorf("%w: person id is required", shared.ErrValidation)
	}
	rows, err := s.pool.Query(ctx, `SELECT tenant_id FROM person_organization_index WHERE person_id=$1 ORDER BY tenant_id`, personID.String())
	if err != nil {
		return nil, fmt.Errorf("list exact person's organizations: %w", err)
	}
	defer rows.Close()
	out := make([]shared.ID, 0)
	for rows.Next() {
		var tenant string
		if err := rows.Scan(&tenant); err != nil {
			return nil, fmt.Errorf("scan exact person's organization: %w", err)
		}
		out = append(out, shared.ID(tenant))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate exact person's organizations: %w", err)
	}
	return out, nil
}
