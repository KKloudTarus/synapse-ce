package postgres

import (
	"context"
	"errors"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NotificationFindingFactsReader captures current ownership and only active,
// same-tenant user identities while the producer transaction remains open.
type NotificationFindingFactsReader struct{ pool *pgxpool.Pool }

func NewNotificationFindingFactsReader(pool *pgxpool.Pool) *NotificationFindingFactsReader {
	return &NotificationFindingFactsReader{pool: pool}
}

var _ ports.NotificationFindingFactsReader = (*NotificationFindingFactsReader)(nil)

func (r *NotificationFindingFactsReader) SnapshotFindingNotificationFacts(ctx context.Context, tenantID, engagementID, findingID, assigneeID shared.ID, actor string) (facts ports.NotificationFindingFacts, err error) {
	if r == nil || r.pool == nil {
		return facts, nil
	}
	err = WithTenant(ctx, r.pool, tenantID.String(), func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT COALESCE(team_id,'') FROM ownership_assignments
			WHERE tenant_id=$1 AND engagement_id=$2 AND finding_id=$3`, tenantID, engagementID, findingID).Scan(&facts.TeamID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		actorID := shared.ID(strings.TrimSpace(actor))
		if !actorID.IsZero() {
			if err := tx.QueryRow(ctx, `SELECT id,name FROM users WHERE `+userTenantPredicate+` AND id=$3 AND NOT disabled`, shared.DefaultTenant.String(), tenantID.String(), actorID.String()).Scan(&facts.ActorUserID, &facts.ActorName); err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		if !assigneeID.IsZero() {
			if err := tx.QueryRow(ctx, `SELECT id FROM users WHERE `+userTenantPredicate+` AND id=$3 AND NOT disabled`, shared.DefaultTenant.String(), tenantID.String(), assigneeID.String()).Scan(&facts.AssigneeUserID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		return nil
	})
	return facts, err
}
