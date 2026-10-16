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
var _ ports.MentionChoiceReader = (*UserPickerReader)(nil)

func (r *UserPickerReader) ListUserChoices(ctx context.Context, tenantID, teamID shared.ID, query string, cursor shared.ID, limit int) ([]ports.UserChoice, error) {
	return r.listChoices(ctx, tenantID, teamID, query, cursor, limit, []string{"admin", "consultant", "reviewer", "member"})
}

// ListMentionChoices includes every active human role that can view a finding.
// Mention validation remains authoritative at the write boundary; this bounded
// projection only supplies valid candidates to the picker.
func (r *UserPickerReader) ListMentionChoices(ctx context.Context, tenantID, teamID shared.ID, query string, cursor shared.ID, limit int) ([]ports.UserChoice, error) {
	return r.listChoices(ctx, tenantID, teamID, query, cursor, limit, []string{"admin", "consultant", "reviewer", "member", "readonly", "integration_admin"})
}

func (r *UserPickerReader) listChoices(ctx context.Context, tenantID, teamID shared.ID, query string, cursor shared.ID, limit int, roles []string) ([]ports.UserChoice, error) {
	query = strings.TrimSpace(query)
	if len(query) > 100 || limit < 1 || limit > 50 {
		return nil, fmt.Errorf("%w: invalid user picker query", shared.ErrValidation)
	}
	tenantID = shared.TenantOrDefault(tenantID)
	out := make([]ports.UserChoice, 0)
	err := WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT u.id,u.name FROM users u WHERE u.ownership_tenant_id=$1 AND NOT u.disabled AND u.role = ANY($6::text[]) AND u.id>$4 AND ($2='' OR EXISTS(SELECT 1 FROM ownership_memberships m WHERE m.tenant_id=$1 AND m.team_id=$2 AND m.user_id=u.id)) AND ($3='' OR POSITION(lower($3) IN lower(u.name))>0 OR POSITION(lower($3) IN lower(u.id))>0) ORDER BY u.id LIMIT $5`, tenantID, teamID, query, cursor, limit, roles)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c ports.UserChoice
			if err := rows.Scan(&c.ID, &c.Name); err != nil {
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
