package postgres

import (
	"context"
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
)

type UserPickerReader struct{ pool *pgxpool.Pool }

func NewUserPickerReader(pool *pgxpool.Pool) *UserPickerReader { return &UserPickerReader{pool: pool} }

var _ ports.UserPickerReader = (*UserPickerReader)(nil)

func (r *UserPickerReader) ListUserChoices(ctx context.Context, tenantID, teamID shared.ID, query string, cursor shared.ID, limit int) ([]ports.UserChoice, error) {
	query = strings.TrimSpace(query)
	if len(query) > 100 || limit < 1 || limit > 50 {
		return nil, fmt.Errorf("%w: invalid user picker query", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	out := make([]ports.UserChoice, 0)
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT u.id,u.name,u.role FROM users u WHERE u.ownership_tenant_id=$1 AND NOT u.disabled AND u.role IN ('admin','consultant','reviewer','member') AND u.id>$4 AND ($2='' OR EXISTS(SELECT 1 FROM ownership_memberships m WHERE m.tenant_id=$1 AND m.team_id=$2 AND m.user_id=u.id)) AND ($3='' OR POSITION(lower($3) IN lower(u.name))>0 OR POSITION(lower($3) IN lower(u.id))>0) ORDER BY u.id LIMIT $5`, tenantID, teamID, query, cursor, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c ports.UserChoice
			if err := rows.Scan(&c.ID, &c.Name, &c.Role); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list user choices: %w", err)
	}
	return out, nil
}
